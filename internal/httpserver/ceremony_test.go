// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Ceremony parity (Phase 2 slice 2): the Go server must reproduce the
// WebAuthn ceremony response envelopes goldened from the Node backend
// (#225/#229), driven end to end by the Go fake authenticator through real
// P-256 crypto. Covers the registration + step-up flows (self-register,
// in-account register, step-up verify); login-verify and invite land with
// their dependencies in later slices.
package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/golden"
	"github.com/rado0x54/shellwatch/internal/hydra"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/webauthn"
	"github.com/rado0x54/shellwatch/internal/webauthntest"
)

const (
	rpID   = "localhost"
	origin = "http://localhost"
)

// Fixed key material from golden-webauthn.test.ts, so derived material
// (credentialId, OpenSSH line) matches the fixtures.
const keyA = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFURdtKNp9vRrua9H
IL7BU5NAx1YUksvk3FMc4JRf60ChRANCAAQvpMYo+35LLiFuv8Mb/+E+SiM2o/fc
iCMQdix5EHFumzvyz+r9NDP8PfipOfiKWj+hObIDlm3B3Tgg9pSL0Jw+
-----END PRIVATE KEY-----`

const keyB = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1rHReRT2jK70bmfr
/HQzcdjkbhuyTAnoSpQIELuPWHqhRANCAARb2s6SmuPtCSbGFCL3IqBATU34YZDP
H9HP58YGEmKIAykoTUreRRPdkD8Ycc7QBehkLxk8wIVGJFr1A/2KWiWH
-----END PRIVATE KEY-----`

func fill(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func fakeA(t *testing.T) *webauthntest.Authenticator {
	t.Helper()
	a, err := webauthntest.New(webauthntest.Options{RpID: rpID, Origin: origin, PrivateKeyPEM: keyA, CredentialID: fill(0x0a)})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func fakeB(t *testing.T) *webauthntest.Authenticator {
	t.Helper()
	a, err := webauthntest.New(webauthntest.Options{RpID: rpID, Origin: origin, PrivateKeyPEM: keyB, CredentialID: fill(0x0b)})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// ceremonyServer wires the webauthn deps against a fresh in-memory DB with a
// resolver that maps a fixed token to whatever account id it's told.
type ceremonyServer struct {
	ts       *httptest.Server
	deps     *webauthn.Deps
	tokenFor func(accountID string) string
}

func newCeremonyServer(t *testing.T, selfReg bool) *ceremonyServer {
	t.Helper()
	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	clk := clock.Real{}
	deps := &webauthn.Deps{
		Credentials:    store.NewCredentials(db, clk),
		Challenges:     webauthn.NewChallengeStore(clk),
		StepUp:         webauthn.NewStepUpStore(clk),
		RpID:           rpID,
		TrustedOrigins: []string{origin},
		SelfRegEnabled: selfReg,
	}

	cfg := &config.Config{}
	cfg.Server.ExternalURL = "https://shellwatch.example"
	cfg.Hydra.PublicURL = "http://localhost:4444"

	// Bearer: "tok-<accountID>" authorizes that account with the ui scope.
	resolve := hydra.Resolver(func(_ context.Context, token string) *hydra.Principal {
		const p = "tok-"
		if len(token) > len(p) && token[:len(p)] == p {
			return &hydra.Principal{AccountID: token[len(p):], Scopes: []string{"ui"}}
		}
		return nil
	})
	handler := New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()),
		BuildInfo: buildinfo.Info{}, WebAuthn: deps,
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return &ceremonyServer{ts: ts, deps: deps, tokenFor: func(id string) string { return "tok-" + id }}
}

func (c *ceremonyServer) post(t *testing.T, path string, body any, headers map[string]string) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, c.ts.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := c.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func assertGolden(t *testing.T, name string, status int, body map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(goldensDir, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected any
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	got := golden.Normalize(map[string]any{"status": float64(status), "body": body}, golden.Options{})
	if !reflect.DeepEqual(got, expected) {
		a, _ := json.MarshalIndent(expected, "", "  ")
		b, _ := json.MarshalIndent(got, "", "  ")
		t.Errorf("golden %s mismatch\n--- expected ---\n%s\n--- got ---\n%s", name, a, b)
	}
}

func challengePair(m map[string]any) (challenge, challengeID string) {
	c, _ := m["challenge"].(string)
	id, _ := m["challengeId"].(string)
	return c, id
}

func TestCeremonySelfRegisterGolden(t *testing.T) {
	c := newCeremonyServer(t, false) // disabled + no passkeys => bootstrap allowed
	_, opts := c.post(t, "/api/auth/register/options", map[string]any{"name": "User"}, nil)
	ch, id := challengePair(opts)
	status, body := c.post(t, "/api/auth/register", map[string]any{
		"name": "User", "challengeId": id, "credential": json.RawMessage(fakeA(t).Register(ch)),
	}, nil)
	assertGolden(t, "webauthn-self-register", status, body)
}

// enroll bootstraps an account with fakeA and returns its id + a bearer.
func (c *ceremonyServer) enroll(t *testing.T) (accountID, bearer string) {
	t.Helper()
	_, opts := c.post(t, "/api/auth/register/options", map[string]any{"name": "User"}, nil)
	ch, id := challengePair(opts)
	_, body := c.post(t, "/api/auth/register", map[string]any{
		"name": "User", "challengeId": id, "credential": json.RawMessage(fakeA(t).Register(ch)),
	}, nil)
	accountID, _ = body["accountId"].(string)
	return accountID, c.tokenFor(accountID)
}

func TestCeremonyStepUpVerifyGolden(t *testing.T) {
	c := newCeremonyServer(t, false)
	accountID, bearer := c.enroll(t)
	authHdr := map[string]string{"Authorization": "Bearer " + bearer}
	fake := fakeA(t) // same key as enrollment

	_, opts := c.post(t, "/api/webauthn/stepup/options",
		map[string]any{"action": webauthn.ActionRegisterPasskey}, authHdr)
	ch, id := challengePair(opts)
	status, body := c.post(t, "/api/webauthn/stepup/verify", map[string]any{
		"challengeId": id, "action": webauthn.ActionRegisterPasskey,
		"credential": json.RawMessage(fake.Authenticate(ch)),
	}, authHdr)
	assertGolden(t, "webauthn-stepup-verify", status, body)
	_ = accountID
}

func TestCeremonyInAccountRegisterGolden(t *testing.T) {
	c := newCeremonyServer(t, false)
	_, bearer := c.enroll(t)
	authHdr := map[string]string{"Authorization": "Bearer " + bearer}
	fake := fakeA(t)

	// Step up for register_passkey.
	_, so := c.post(t, "/api/webauthn/stepup/options",
		map[string]any{"action": webauthn.ActionRegisterPasskey}, authHdr)
	sch, sid := challengePair(so)
	_, sv := c.post(t, "/api/webauthn/stepup/verify", map[string]any{
		"challengeId": sid, "action": webauthn.ActionRegisterPasskey,
		"credential": json.RawMessage(fake.Authenticate(sch)),
	}, authHdr)
	stepToken, _ := sv["stepUpToken"].(string)

	// Register a SECOND key (fakeB) -> label "Passkey (2)", stable OpenSSH line.
	_, opts := c.post(t, "/api/webauthn/register/options", map[string]any{"label": "Second Key"}, authHdr)
	ch, id := challengePair(opts)
	status, body := c.post(t, "/api/webauthn/register", map[string]any{
		"challengeId": id, "credential": json.RawMessage(fakeB(t).Register(ch)),
	}, map[string]string{"Authorization": "Bearer " + bearer, "X-Shellwatch-Stepup-Token": stepToken})
	assertGolden(t, "webauthn-register", status, body)
}

var _ = auth.UIScope
