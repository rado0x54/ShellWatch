// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Shape parity for the remaining #234 goldens on already-built routes (meta,
// endpoint mutation, sessions, pending actions, DCR). Complements the
// account/credential/auth/push goldens; together with the route-coverage guard
// this closes the "golden-covered != contract-covered" gap.
package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/rest"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
	"github.com/rado0x54/shellwatch/internal/webauthn"
)

// --- Meta (build info) ---

func TestMetaVersionGolden(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	handler := New(Params{
		Config: cfg, Resolve: auth.Resolver(func(context.Context, string) *auth.Principal { return nil }),
		StaticFS:  os.DirFS(t.TempDir()),
		BuildInfo: buildinfo.Info{Sha: "dev", Ref: "local", Display: "local@dev"},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	res, err := ts.Client().Get(ts.URL + "/api/version")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	assertEnvelope(t, "meta-version", "/api/version", res.StatusCode, decode(t, res.Body))
}

// --- Endpoint update (already-built route, new golden) ---

func TestEndpointUpdateGolden(t *testing.T) {
	ts, _ := endpointsServer(t)
	s, b := doJSON(t, ts, "PUT", "/api/endpoints/test-server", `{"label":"Renamed"}`)
	assertEnvelope(t, "endpoint-update", "/api/endpoints/test-server", s, b)
}

// --- Sessions create/list (test-account + test-server ids from the golden) ---

func sessionGoldenServer(t *testing.T) *httptest.Server {
	t.Helper()
	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db.ExecContext(ctx, `INSERT INTO accounts (id,name,max_sessions,created_at,updated_at) VALUES (?,'A',5,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, acct)
	db.ExecContext(ctx, `INSERT INTO endpoints (id,account_id,label,host,port,username,user_verification,agent_forward,enabled,created_at,updated_at) VALUES ('test-server',?,'E','h',22,'u','required',1,1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, acct)
	mgr := terminal.NewManager(func(context.Context, terminal.FactoryParams) (terminal.Transport, error) {
		return terminal.NewMockTransport(), nil
	}, clock.Real{}, 0)
	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	resolve := auth.Resolver(func(_ context.Context, tok string) *auth.Principal {
		if tok == "ui" {
			return &auth.Principal{AccountID: acct, Scopes: []string{"ui"}}
		}
		return nil
	})
	handler := New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
		Sessions: &rest.Sessions{Manager: mgr, Endpoints: store.NewEndpoints(db, clock.Real{})},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

func TestSessionCreateListGoldens(t *testing.T) {
	ts := sessionGoldenServer(t)
	s, b := doJSON(t, ts, "POST", "/api/sessions", `{"endpointId":"test-server"}`)
	assertEnvelope(t, "session-create", "/api/sessions", s, b)

	s, b = doJSON(t, ts, "GET", "/api/sessions", "")
	assertEnvelope(t, "session-list", "/api/sessions", s, b)
}

// --- Pending actions get/resolve/deny (shared in-memory store) ---

func actionsGoldenServer(t *testing.T) (*httptest.Server, *approval.Store) {
	t.Helper()
	as := approval.NewStore(clock.Real{}, func() string { return "act_fixed_0000000000000001" })
	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	resolve := auth.Resolver(func(_ context.Context, tok string) *auth.Principal {
		if tok == "ui" {
			return &auth.Principal{AccountID: acct, Scopes: []string{"ui"}}
		}
		return nil
	})
	handler := New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
		Actions: &rest.Actions{Store: as},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts, as
}

func seedKeyAction(as *approval.Store) *approval.Action {
	return as.Create(approval.CreateParams{
		AccountID: acct, Type: approval.TypeKeyApprove, RedirectTo: "/sign/approved",
		KeyLabel: "Deploy Key", KeyFingerprint: "SHA256:Rml4ZWREZXRlcm1pbmlzdGljRmluZ2VycHJpbnQ",
		Context: approval.Context{
			Source: "endpoint-auth", EndpointLabel: "Prod DB", EndpointAddress: "deploy@db.internal:2222",
			TriggerKind: "mcp", MCPReason: "deploy hotfix", MCPClientName: "codex",
		},
		ResolveKey: func() {},
	})
}

func TestActionGoldens(t *testing.T) {
	ts, as := actionsGoldenServer(t)

	a := seedKeyAction(as)
	s, b := doJSON(t, ts, "GET", "/api/actions/"+a.ID, "")
	// The action id isn't a normalizer-recognized shape; the golden folds it by
	// hand (see golden-actions-push.test.ts snapAction).
	b["id"] = "<ID>"
	assertEnvelope(t, "action-get", "/api/actions/{actionId}", s, b)

	// resolve on a fresh action -> { redirectTo }.
	a2 := seedKeyAction(as)
	s, b = doJSON(t, ts, "POST", "/api/actions/"+a2.ID+"/resolve", `{}`)
	assertEnvelope(t, "action-resolve", "/api/actions/{actionId}/resolve", s, b)

	// deny on a fresh action -> { status: denied }.
	a3 := seedKeyAction(as)
	s, b = doJSON(t, ts, "POST", "/api/actions/"+a3.ID+"/deny", `{}`)
	assertEnvelope(t, "action-deny", "/api/actions/{actionId}/deny", s, b)
}

func decode(t *testing.T, r io.Reader) map[string]any {
	t.Helper()
	out := map[string]any{}
	_ = json.NewDecoder(r).Decode(&out)
	return out
}

// --- Endpoint validation error goldens (older, previously unasserted) ---

func TestErr400EndpointGoldens(t *testing.T) {
	ts, _ := endpointsServer(t)
	s, b := doJSON(t, ts, "POST", "/api/endpoints", `{"host":"h"}`)
	assertEnvelope(t, "err-400-endpoint-missing-fields", "/api/endpoints", s, b)

	s, b = doJSON(t, ts, "POST", "/api/endpoints", `{"label":"L","host":"h","userVerification":"bogus"}`)
	assertEnvelope(t, "err-400-endpoint-create", "/api/endpoints", s, b)
}

// --- Mediated DCR ---

func TestDCRRegisterGolden(t *testing.T) {
	ts, _, _, _ := authedApp(t, nil)
	res, err := ts.Client().Post(ts.URL+"/api/hydra/register", "application/json",
		strings.NewReader(`{"client_name":"Test MCP","redirect_uris":["http://127.0.0.1:9876/callback"],"scope":"mcp"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	assertEnvelope(t, "dcr-register", "/api/hydra/register", res.StatusCode, decode(t, res.Body))
}

// --- Passkey invites ---

func TestInviteGoldens(t *testing.T) {
	ts, db, _, _ := authedApp(t, nil)
	exec(t, db, `INSERT INTO accounts (id,name,created_at,updated_at) VALUES (?,'Admin','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')`, acct)
	exec(t, db, `INSERT INTO admin_account (singleton, account_id) VALUES (1, ?)`, acct)

	// Mint a slot, then GET returns it (token redacted).
	req(t, ts, "POST", "/api/webauthn/invite", "", "")
	s, b := req(t, ts, "GET", "/api/webauthn/invite", "", "")
	assertEnvelope(t, "invite-get", "/api/webauthn/invite", s, b)

	// Mint again, read the token, resolve it publicly.
	_, mint := req(t, ts, "POST", "/api/webauthn/invite", "", "")
	token := mint["invite"].(map[string]any)["token"].(string)
	res, err := ts.Client().Get(ts.URL + "/api/passkey-invite/" + token)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	assertEnvelope(t, "invite-by-token", "/api/passkey-invite/<REDACTED>", res.StatusCode, decode(t, res.Body))
}

// --- Credential confirm (step-up) ---

func TestCredentialConfirmGolden(t *testing.T) {
	ts, db, _, stepUp := authedApp(t, nil)
	exec(t, db, `INSERT INTO accounts (id,name,created_at,updated_at) VALUES (?,'Admin','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')`, acct)
	cose := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01}
	exec(t, db, `INSERT INTO webauthn_credentials (id,account_id,credential_id,public_key,counter,label,public_key_openssh,revoked,state,created_at) VALUES ('cred-pending-1',?,'Y3JlZC1wZW5kaW5nLTE',?,0,'Pending Device','sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNh pending',0,'pending_confirmation','2026-01-01T00:00:00.000Z')`, acct, cose)

	tok := "stepup-confirm"
	stepUp.Mint(tok, acct, webauthn.ActionConfirmPasskey)
	s, b := req(t, ts, "POST", "/api/webauthn/credentials/cred-pending-1/confirm", `{}`, tok)
	assertEnvelope(t, "credential-confirm", "/api/webauthn/credentials/cred-pending-1/confirm", s, b)
}

// --- Browser bootstrap (/config.js): a byte-exact JS string + contentType ---

func TestMetaConfigJSGolden(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.ExternalURL = "http://localhost:3000"
	cfg.Hydra.PublicURL = "http://localhost:4444"
	cfg.Hydra.Spa.ClientID = "shellwatch-web"
	handler := New(Params{
		Config: cfg, Resolve: auth.Resolver(func(context.Context, string) *auth.Principal { return nil }),
		StaticFS:  os.DirFS(t.TempDir()),
		BuildInfo: buildinfo.Info{Sha: "dev", Ref: "local", Display: "local@dev"},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	res, err := ts.Client().Get(ts.URL + "/config.js")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	buf := new(strings.Builder)
	io.Copy(buf, res.Body)

	var golden struct {
		Status      int    `json:"status"`
		ContentType string `json:"contentType"`
		Body        string `json:"body"`
	}
	raw, _ := os.ReadFile("../../src/test/integration/__goldens__/meta-config-js.json")
	json.Unmarshal(raw, &golden)

	ct := res.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, golden.ContentType) {
		t.Errorf("content-type: got %q want prefix %q", ct, golden.ContentType)
	}
	if buf.String() != golden.Body {
		t.Errorf("config.js body mismatch\n--- golden ---\n%s\n--- go ---\n%s", golden.Body, buf.String())
	}
}
