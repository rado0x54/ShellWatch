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
	"github.com/rado0x54/shellwatch/internal/golden"
	"github.com/rado0x54/shellwatch/internal/rest"
	"github.com/rado0x54/shellwatch/internal/store"
)

const seedPort = int64(49871) // per-run-style port folded to <PORT>

func endpointsServer(t *testing.T) (*httptest.Server, string) {
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
	handler := New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
		Endpoints: &rest.Endpoints{
			Store: store.NewEndpoints(db, clock.Real{}),
			NewID: func() string { return "11111111-2222-4333-8444-555555555555" },
		},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts, ts.URL
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
