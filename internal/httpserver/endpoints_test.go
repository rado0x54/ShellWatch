// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Endpoints REST parity (Phase 3 slice 1): the Go server reproduces the
// endpoints-list / endpoints-create goldens and the 400 validation matrix.
package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/endpointsvc"
	"github.com/rado0x54/shellwatch/internal/golden"
	"github.com/rado0x54/shellwatch/internal/rest"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/webauthn"
)

const seedPort = int64(49871) // per-run-style port folded to <PORT>

func endpointsServer(t *testing.T) (*httptest.Server, *webauthn.StepUpStore) {
	t.Helper()
	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	// Seed an account + the golden's "test-server" endpoint.
	ctx := context.Background()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO accounts (id, name, created_at, updated_at) VALUES ('acc', 'A', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO endpoints (id, account_id, label, host, port, username, user_verification, agent_forward, enabled, created_at, updated_at)
		 VALUES ('test-server','acc','Test Server','127.0.0.1',?,'testuser','required',1,1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, seedPort); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"

	resolve := auth.Resolver(func(_ context.Context, token string) *auth.Principal {
		if token == "ui" {
			return &auth.Principal{AccountID: "acc", Scopes: []string{"ui"}}
		}
		return nil
	})
	stepUp := webauthn.NewStepUpStore(clock.Real{})
	handler := New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
		Endpoints: &rest.Endpoints{
			Svc:    &endpointsvc.Service{Endpoints: store.NewEndpoints(db, clock.Real{})},
			NewID:  func() string { return "11111111-2222-4333-8444-555555555555" },
			StepUp: stepUp,
		},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts, stepUp
}

func doJSON(t *testing.T, ts *httptest.Server, method, path, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer ui")
	req.Header.Set("Content-Type", "application/json")
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func TestEndpointsListGolden(t *testing.T) {
	ts, _ := endpointsServer(t)
	status, body := doJSON(t, ts, "GET", "/api/endpoints", "")
	got := golden.Normalize(
		map[string]any{"request": map[string]any{"path": "/api/endpoints"}, "status": float64(status), "body": body},
		golden.Options{BaseURLs: []string{ts.URL}, Ports: []float64{float64(seedPort)}})
	raw, _ := os.ReadFile(filepath.Join(goldensDir, "endpoints-list.json"))
	var expected any
	_ = json.Unmarshal(raw, &expected)
	if !reflect.DeepEqual(got, expected) {
		a, _ := json.MarshalIndent(expected, "", "  ")
		b, _ := json.MarshalIndent(got, "", "  ")
		t.Errorf("endpoints-list mismatch\n--- golden ---\n%s\n--- go ---\n%s", a, b)
	}
}

func TestEndpointsCreateGolden(t *testing.T) {
	ts, _ := endpointsServer(t)
	status, body := doJSON(t, ts, "POST", "/api/endpoints",
		`{"label":"Golden Box","host":"golden.example","username":"gold"}`)
	got := golden.Normalize(map[string]any{"request": map[string]any{"path": "/api/endpoints"},
		"status": float64(status), "body": body}, golden.Options{})
	raw, _ := os.ReadFile(filepath.Join(goldensDir, "endpoints-create.json"))
	var expected any
	_ = json.Unmarshal(raw, &expected)
	if !reflect.DeepEqual(got, expected) {
		a, _ := json.MarshalIndent(expected, "", "  ")
		b, _ := json.MarshalIndent(got, "", "  ")
		t.Errorf("endpoints-create mismatch\n--- golden ---\n%s\n--- go ---\n%s", a, b)
	}
}

func TestEndpointsValidationMatrix(t *testing.T) {
	ts, _ := endpointsServer(t)
	cases := []struct {
		body   string
		status int
		errMsg string
	}{
		{`{"host":"h"}`, 400, "label and host are required"},
		{`{"label":"  ","host":"h"}`, 400, "label and host are required"},
		{`{"label":"L","host":"h","userVerification":"bogus"}`, 400, "userVerification must be one of: required, preferred, discouraged"},
		{`{"label":"L","host":"h","agentForward":"yes"}`, 400, "agentForward must be a boolean"},
	}
	for _, tc := range cases {
		status, body := doJSON(t, ts, "POST", "/api/endpoints", tc.body)
		if status != tc.status || body["error"] != tc.errMsg {
			t.Errorf("body %s: got %d %q", tc.body, status, body["error"])
		}
	}
}

// --- Host-key management (#241): pin + forget, both step-up gated ---

// doJSONStepUp is doJSON with an X-Shellwatch-Stepup-Token header.
func doJSONStepUp(t *testing.T, ts *httptest.Server, method, path, body, token string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer ui")
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Shellwatch-Stepup-Token", token)
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

const testHostKeyLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPLKV/zrLbSGFbSEOz6h3NwcnZ2TV1lLgcdB2z/+xwj7 test-host"

func assertEndpointGolden(t *testing.T, name, path string, status int, body map[string]any) {
	t.Helper()
	got := golden.Normalize(
		map[string]any{"request": map[string]any{"path": path}, "status": float64(status), "body": body},
		golden.Options{})
	raw, _ := os.ReadFile(filepath.Join(goldensDir, name+".json"))
	var expected any
	_ = json.Unmarshal(raw, &expected)
	if !reflect.DeepEqual(got, expected) {
		a, _ := json.MarshalIndent(expected, "", "  ")
		b, _ := json.MarshalIndent(got, "", "  ")
		t.Errorf("%s mismatch\n--- golden ---\n%s\n--- go ---\n%s", name, a, b)
	}
}

func TestEndpointHostKeyPinGolden(t *testing.T) {
	ts, stepUp := endpointsServer(t)

	// No step-up token -> 401 {error, code}.
	if status, body := doJSONStepUp(t, ts, "PUT", "/api/endpoints/test-server/host-key",
		`{"publicKey":"`+testHostKeyLine+`"}`, ""); status != 401 || body["code"] != "stepup_required" {
		t.Fatalf("unauthenticated pin: status=%d body=%v", status, body)
	}

	stepUp.Mint("tok-pin", "acc", webauthn.ActionPinHostKey)
	status, body := doJSONStepUp(t, ts, "PUT", "/api/endpoints/test-server/host-key",
		`{"publicKey":"`+testHostKeyLine+`"}`, "tok-pin")
	assertEndpointGolden(t, "endpoint-hostkey-pin", "/api/endpoints/test-server/host-key", status, body)

	// The pin surfaces on the endpoint list.
	_, list := doJSON(t, ts, "GET", "/api/endpoints", "")
	eps := list["endpoints"].([]any)
	hk, _ := eps[0].(map[string]any)["hostKey"].(map[string]any)
	if hk == nil || hk["type"] != "ssh-ed25519" || hk["pinnedBy"] != "manual" ||
		!strings.HasPrefix(hk["fingerprint"].(string), "SHA256:") {
		t.Fatalf("pinned hostKey not surfaced on list: %v", eps[0])
	}

	// Compare-and-set: a second pin with a different key is a 409.
	stepUp.Mint("tok-pin-2", "acc", webauthn.ActionPinHostKey)
	if status, body := doJSONStepUp(t, ts, "PUT", "/api/endpoints/test-server/host-key",
		`{"fingerprint":"SHA256:differentdifferentdifferentdifferentdiffe"}`, "tok-pin-2"); status != 409 {
		t.Fatalf("conflicting pin: status=%d body=%v", status, body)
	}
}

func TestEndpointHostKeyDeleteGolden(t *testing.T) {
	ts, stepUp := endpointsServer(t)
	stepUp.Mint("tok-pin", "acc", webauthn.ActionPinHostKey)
	if status, _ := doJSONStepUp(t, ts, "PUT", "/api/endpoints/test-server/host-key",
		`{"publicKey":"`+testHostKeyLine+`"}`, "tok-pin"); status != 200 {
		t.Fatalf("pin failed: %d", status)
	}

	// Wrong-action token (pin token on the delete route) -> 401.
	stepUp.Mint("tok-wrong", "acc", webauthn.ActionPinHostKey)
	if status, body := doJSONStepUp(t, ts, "DELETE", "/api/endpoints/test-server/host-key", "", "tok-wrong"); status != 401 || body["code"] != "stepup_wrong_action" {
		t.Fatalf("wrong-action delete: status=%d body=%v", status, body)
	}

	stepUp.Mint("tok-del", "acc", webauthn.ActionResetHostKey)
	status, body := doJSONStepUp(t, ts, "DELETE", "/api/endpoints/test-server/host-key", "", "tok-del")
	assertEndpointGolden(t, "endpoint-hostkey-delete", "/api/endpoints/test-server/host-key", status, body)

	// Gone from the list again.
	_, list := doJSON(t, ts, "GET", "/api/endpoints", "")
	if hk := list["endpoints"].([]any)[0].(map[string]any)["hostKey"]; hk != nil {
		t.Fatalf("hostKey still set after delete: %v", hk)
	}
}

func TestEndpointUpdateHostPortClearsPin(t *testing.T) {
	ts, stepUp := endpointsServer(t)
	stepUp.Mint("tok-pin", "acc", webauthn.ActionPinHostKey)
	if status, _ := doJSONStepUp(t, ts, "PUT", "/api/endpoints/test-server/host-key",
		`{"publicKey":"`+testHostKeyLine+`"}`, "tok-pin"); status != 200 {
		t.Fatal("pin failed")
	}

	// Label-only update keeps the pin.
	if status, _ := doJSON(t, ts, "PUT", "/api/endpoints/test-server", `{"label":"Renamed"}`); status != 200 {
		t.Fatal("update failed")
	}
	_, list := doJSON(t, ts, "GET", "/api/endpoints", "")
	if hk := list["endpoints"].([]any)[0].(map[string]any)["hostKey"]; hk == nil {
		t.Fatal("label update must keep the pin")
	}

	// Host change clears it.
	if status, _ := doJSON(t, ts, "PUT", "/api/endpoints/test-server", `{"host":"other.example"}`); status != 200 {
		t.Fatal("update failed")
	}
	_, list = doJSON(t, ts, "GET", "/api/endpoints", "")
	if hk := list["endpoints"].([]any)[0].(map[string]any)["hostKey"]; hk != nil {
		t.Fatalf("host change must clear the pin, still: %v", hk)
	}
}
