// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Parity for the account/auth self-service + admin + push + consent REST
// surfaces added to reach full contract coverage. Each golden group builds its
// own seeded server (mirroring the Node golden-account/credentials/hydra/
// actions-push test files) and asserts the {request,status,body} envelope.
package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/hydra"
	"github.com/rado0x54/shellwatch/internal/hydratest"
	"github.com/rado0x54/shellwatch/internal/rest"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/webauthn"
)

const acct = "test-account-00000000-0000-0000-0000-000000000000"

// authedApp wires every account/auth route group over a fresh DB and returns
// the server, DB, fake Hydra, and the step-up store (to mint gated-action
// tokens). Token "ui" resolves to the admin account.
func authedApp(t *testing.T, demoEndpoints []config.SeedEndpoint) (*httptest.Server, *sql.DB, *hydratest.FakeAdmin, *webauthn.StepUpStore) {
	t.Helper()
	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	cfg.Hydra.Spa.ClientID = "shellwatch-web"

	fake := hydratest.New()
	stepUp := webauthn.NewStepUpStore(clock.Real{})
	credStore := store.NewCredentials(db, clock.Real{})
	demoSvc := demo.NewService(demoEndpoints)
	resolve := auth.Resolver(func(_ context.Context, token string) *auth.Principal {
		if token == "ui" {
			return &auth.Principal{AccountID: acct, Scopes: []string{"ui"}}
		}
		return nil
	})
	handler := New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
		HydraAdmin: fake,
		Accounts: &rest.Accounts{
			Store: store.NewAccounts(db), Creds: credStore, Endpoints: store.NewEndpoints(db, clock.Real{}),
			Demo: demoSvc, Now: func() string { return "2026-07-02T10:00:00.000Z" },
		},
		Credentials: &rest.Credentials{Store: credStore, Admin: fake, StepUp: stepUp},
		Keys:        &rest.Keys{Store: store.NewSSHKeys(db), Accounts: store.NewAccounts(db)},
		AuthSessions: &rest.AuthSessions{
			Admin: fake, SPAClientID: "shellwatch-web", StepUp: stepUp,
		},
		Push: &rest.Push{Store: store.NewPushSubs(db, clock.Real{}), NewID: func() string { return "11111111-2222-4333-8444-555555555555" }},
		WebAuthn: &webauthn.Deps{
			Credentials: credStore, Challenges: webauthn.NewChallengeStore(clock.Real{}),
			StepUp: stepUp, RpID: "localhost",
		},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts, db, fake, stepUp
}

// req sends an authed request (optionally with a step-up token) and returns the
// status + decoded body.
func req(t *testing.T, ts *httptest.Server, method, path, body, stepUpToken string) (int, map[string]any) {
	t.Helper()
	r, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer ui")
	r.Header.Set("Content-Type", "application/json")
	if stepUpToken != "" {
		r.Header.Set("X-Shellwatch-Stepup-Token", stepUpToken)
	}
	res, err := ts.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func exec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// --- Account + keys + export (golden-account seed) ---

func seedAccountGroup(t *testing.T, db *sql.DB) {
	const ts = "2026-01-01T00:00:00.000Z"
	exec(t, db, `INSERT INTO accounts (id,name,enabled,max_sessions,show_demo_endpoints,created_at,updated_at) VALUES (?,'Admin',1,5,1,?,?)`, acct, ts, ts)
	exec(t, db, `INSERT INTO accounts (id,name,enabled,max_sessions,show_demo_endpoints,created_at,updated_at) VALUES ('22222222-2222-2222-2222-222222222222','Bob',1,3,1,'2026-01-02T00:00:00.000Z','2026-01-02T00:00:00.000Z')`)
	exec(t, db, `INSERT INTO admin_account (singleton, account_id) VALUES (1, ?)`, acct)
	exec(t, db, `INSERT INTO endpoints (id,account_id,label,host,port,username,user_verification,agent_forward,enabled,created_at,updated_at) VALUES ('ep-seed-1',?,'Prod DB','db.internal',2222,'deploy','required',1,1,?,?)`, acct, ts, ts)
	exec(t, db, `INSERT INTO webauthn_credentials (id,account_id,credential_id,public_key,counter,transports,label,public_key_openssh,revoked,state,created_at) VALUES ('cred-row-1',?,'Y29yZS1jcmVkLWE',x'a5010203262001',0,?,'Primary Passkey',?,0,'active',?)`,
		acct, `["internal","hybrid"]`, "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBEZJWEVE shellwatch", ts)
	exec(t, db, `INSERT INTO ssh_keys (id,label,type,public_key,fingerprint,enabled,created_at,updated_at) VALUES ('key-1','Deploy Key','file',?,'SHA256:Rml4ZWREZXRlcm1pbmlzdGljRmluZ2VycHJpbnRWYWx1ZQ',1,?,?)`,
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZJWEVEREVURVJNSU5JU1RJQ0tFWU1BVEVSSUFM deploy@shellwatch", ts, ts)
}

func TestAccountGoldens(t *testing.T) {
	ts, db, _, _ := authedApp(t, nil)
	seedAccountGroup(t, db)

	s, b := req(t, ts, "GET", "/api/auth/me", "", "")
	assertEnvelope(t, "account-me", "/api/auth/me", s, b)

	s, b = req(t, ts, "PUT", "/api/auth/me", `{"name":"Admin"}`, "")
	assertEnvelope(t, "account-update", "/api/auth/me", s, b)

	s, b = req(t, ts, "GET", "/api/accounts", "", "")
	assertEnvelope(t, "account-list", "/api/accounts", s, b)

	s, b = req(t, ts, "GET", "/api/accounts/export-seed", "", "")
	assertEnvelope(t, "account-export-seed", "/api/accounts/export-seed", s, b)

	s, b = req(t, ts, "GET", "/api/keys", "", "")
	assertEnvelope(t, "keys-list", "/api/keys", s, b)

	s, b = req(t, ts, "DELETE", "/api/accounts/22222222-2222-2222-2222-222222222222", "", "")
	assertEnvelope(t, "account-delete", "/api/accounts/22222222-2222-2222-2222-222222222222", s, b)
}

// --- Credentials list/label/revoke (golden-credentials seed: 3 creds) ---

func seedCredentialsGroup(t *testing.T, db *sql.DB) {
	const ts = "2026-01-01T00:00:00.000Z"
	exec(t, db, `INSERT INTO accounts (id,name,created_at,updated_at) VALUES (?,'Admin',?,?)`, acct, ts, ts)
	exec(t, db, `INSERT INTO admin_account (singleton, account_id) VALUES (1, ?)`, acct)
	cose := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0xaa, 0x25, 0x58, 0x20, 0xbb}
	add := func(id, credID, label, openssh, state string) {
		exec(t, db, `INSERT INTO webauthn_credentials (id,account_id,credential_id,public_key,counter,label,public_key_openssh,revoked,state,created_at) VALUES (?,?,?,?,0,?,?,0,?,?)`,
			id, acct, credID, cose, label, openssh, state, ts)
	}
	add("cred-active-1", "Y3JlZC1hY3RpdmUtMQ", "Primary", "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhAAAACG5pc3RwMjU2AAAAQQRQUklNQVJZ primary", "active")
	add("cred-active-2", "Y3JlZC1hY3RpdmUtMg", "Backup", "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhAAAACG5pc3RwMjU2AAAAQQRCQUNLVVA backup", "active")
	add("cred-pending-1", "Y3JlZC1wZW5kaW5nLTE", "Pending Device", "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhAAAACG5pc3RwMjU2AAAAQQRQRU5ESU5H pending", "pending_confirmation")
}

func TestCredentialsGoldens(t *testing.T) {
	ts, db, _, stepUp := authedApp(t, nil)
	seedCredentialsGroup(t, db)

	s, b := req(t, ts, "GET", "/api/webauthn/credentials", "", "")
	assertEnvelope(t, "credentials-list", "/api/webauthn/credentials", s, b)

	s, b = req(t, ts, "PATCH", "/api/webauthn/credentials/cred-active-1/label", `{"label":"Renamed"}`, "")
	assertEnvelope(t, "credential-label", "/api/webauthn/credentials/cred-active-1/label", s, b)

	tok := "stepup-revoke-tok"
	stepUp.Mint(tok, acct, webauthn.ActionRevokePasskey)
	s, b = req(t, ts, "POST", "/api/webauthn/credentials/cred-active-2/revoke", `{}`, tok)
	assertEnvelope(t, "credential-revoke", "/api/webauthn/credentials/cred-active-2/revoke", s, b)
}

// --- Authorized clients + consent-approve (golden-hydra seed via fake) ---

func TestAuthSessionsGoldens(t *testing.T) {
	ts, db, fake, stepUp := authedApp(t, nil)
	exec(t, db, `INSERT INTO accounts (id,name,created_at,updated_at) VALUES (?,'Admin','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')`, acct)
	fake.SetConsentSessions(acct, []hydra.ConsentSession{
		{GrantScope: []string{"ui", "offline_access"}, HandledAt: "2026-01-01T00:00:00Z",
			ConsentRequest: &struct {
				Client hydra.OAuth2Client `json:"client"`
			}{Client: hydra.OAuth2Client{ClientID: "shellwatch-web", ClientName: "ShellWatch Web"}}},
		{GrantScope: []string{"mcp", "offline_access"}, HandledAt: "2026-02-01T00:00:00Z",
			ConsentRequest: &struct {
				Client hydra.OAuth2Client `json:"client"`
			}{Client: hydra.OAuth2Client{ClientID: "mcp-abc", ClientName: "Claude MCP", CreatedAt: "2026-01-30Z"}}},
	})

	s, b := req(t, ts, "GET", "/api/auth/sessions", "", "")
	assertEnvelope(t, "auth-sessions-list", "/api/auth/sessions", s, b)

	tok := "stepup-revoke-session"
	stepUp.Mint(tok, acct, webauthn.ActionRevokeSession)
	s, b = req(t, ts, "DELETE", "/api/auth/sessions/mcp-abc", "", tok)
	assertEnvelope(t, "auth-session-revoke", "/api/auth/sessions/mcp-abc", s, b)

	tok2 := "stepup-revoke-all"
	stepUp.Mint(tok2, acct, webauthn.ActionRevokeAllSessions)
	s, b = req(t, ts, "POST", "/api/auth/sessions/revoke-all", `{}`, tok2)
	assertEnvelope(t, "auth-session-revoke-all", "/api/auth/sessions/revoke-all", s, b)

	// consent-approve is not bearer-gated; seed a fresh-login consent challenge.
	fake.SetConsentRequest("consent-approve-chal", hydra.ConsentRequest{
		Challenge: "consent-approve-chal", Subject: acct,
		Client:         hydra.OAuth2Client{ClientID: "mcp-abc", ClientName: "Claude MCP"},
		RequestedScope: []string{"mcp", "offline_access"},
		Context:        map[string]any{"freshLogin": true},
	})
	res, err := ts.Client().Post(ts.URL+"/api/hydra/consent/approve", "application/json",
		strings.NewReader(`{"consent_challenge":"consent-approve-chal"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	cb := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&cb)
	assertEnvelope(t, "consent-approve", "/api/hydra/consent/approve", res.StatusCode, cb)
}

// --- Push subscribe/unsubscribe (golden-actions-push seed) ---

func TestPushGoldens(t *testing.T) {
	ts, db, _, _ := authedApp(t, nil)
	exec(t, db, `INSERT INTO accounts (id,name,created_at,updated_at) VALUES (?,'Admin','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')`, acct)

	s, b := req(t, ts, "POST", "/api/push/subscribe",
		`{"endpoint":"https://fcm.googleapis.com/fcm/send/abc","keys":{"p256dh":"pk","auth":"au"}}`, "")
	assertEnvelope(t, "push-subscribe", "/api/push/subscribe", s, b)

	s, b = req(t, ts, "DELETE", "/api/push/subscribe",
		`{"endpoint":"https://fcm.googleapis.com/fcm/send/abc"}`, "")
	assertEnvelope(t, "push-unsubscribe", "/api/push/subscribe", s, b)
}
