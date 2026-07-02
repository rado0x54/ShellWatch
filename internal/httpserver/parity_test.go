// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Parity: the GO server must reproduce the same stateless goldens the
// harness was proven against on the Node server (Phase 1). This is the
// rewrite's acceptance gate applied to the first Go surfaces: health, the
// 401 matrix of the bearer gate, and the discovery documents.
package httpserver

import (
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
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/golden"
)

const goldensDir = "../../src/test/integration/__goldens__"

// externalURL is pinned like the Node golden suite pins it, so discovery
// bodies are stable independent of the per-run listen port.
const externalURL = "https://shellwatch.example"

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	cfg.AgentSocket.ProxyEnabled = true // the golden app mounts the proxy

	// No valid tokens exist in this suite — the resolver denies everything,
	// which is exactly what the 401 goldens capture.
	deny := auth.Resolver(func(context.Context, string) *auth.Principal { return nil })

	handler := New(Params{
		Config:    cfg,
		Resolve:   deny,
		StaticFS:  os.DirFS(t.TempDir()),
		BuildInfo: buildinfo.Info{Sha: "dev", Ref: "local", Display: "local@dev"},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

var statelessGoldens = []string{
	"health",
	"err-401-api",
	"err-401-mcp",
	"discovery-protected-resource",
	"discovery-protected-resource-mcp",
	"discovery-protected-resource-agent",
	"discovery-authorization-server",
}

func TestGoServerMatchesStatelessGoldens(t *testing.T) {
	ts := testServer(t)
	baseURLs := []string{ts.URL, externalURL}

	for _, name := range statelessGoldens {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(goldensDir, name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			normalized, expected, err := golden.ReplayGET(ts.Client(), ts.URL, raw, baseURLs)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(normalized, expected) {
				a, _ := json.MarshalIndent(expected, "", "  ")
				b, _ := json.MarshalIndent(normalized, "", "  ")
				t.Errorf("parity mismatch\n--- golden ---\n%s\n--- go server (normalized) ---\n%s", a, b)
			}
		})
	}
}

// TestGateScopeMatrix covers the gate behaviors the goldens don't: invalid
// tokens, wrong scope (403 + insufficient_scope), the /ws subprotocol path,
// and exemptions.
func TestGateScopeMatrix(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	cfg.AgentSocket.ProxyEnabled = true

	resolve := auth.Resolver(func(_ context.Context, token string) *auth.Principal {
		switch token {
		case "ui-token":
			return &auth.Principal{AccountID: "acc-ui", Scopes: []string{"ui"}}
		case "mcp-token":
			return &auth.Principal{AccountID: "acc-mcp", Scopes: []string{"mcp"}}
		}
		return nil
	})
	var touched []string
	handler := New(Params{
		Config:        cfg,
		Resolve:       resolve,
		TouchLastUsed: func(id string) { touched = append(touched, id) },
		StaticFS:      os.DirFS(t.TempDir()),
		BuildInfo:     buildinfo.Info{},
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	get := func(path string, header map[string]string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		for k, v := range header {
			req.Header.Set(k, v)
		}
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res
	}

	if res := get("/api/endpoints", map[string]string{"Authorization": "Bearer bogus"}); res.StatusCode != 401 {
		t.Errorf("invalid token: got %d", res.StatusCode)
	}
	if res := get("/api/endpoints", map[string]string{"Authorization": "Bearer mcp-token"}); res.StatusCode != 403 {
		t.Errorf("wrong scope must 403: got %d", res.StatusCode)
	} else if h := res.Header.Get("Www-Authenticate"); h != `Bearer realm="shellwatch", error="insufficient_scope"` {
		t.Errorf("scope WWW-Authenticate: %q", h)
	}
	// /ws accepts the subprotocol fallback (404 after the gate: no WS route
	// mounted yet — anything but 401/403 means the gate admitted it).
	if res := get("/ws", map[string]string{"Sec-WebSocket-Protocol": "shellwatch.bearer, ui-token"}); res.StatusCode == 401 || res.StatusCode == 403 {
		t.Errorf("/ws subprotocol token rejected: %d", res.StatusCode)
	}
	// The subprotocol channel must NOT work off /ws.
	if res := get("/api/endpoints", map[string]string{"Sec-WebSocket-Protocol": "shellwatch.bearer, ui-token"}); res.StatusCode != 401 {
		t.Errorf("subprotocol off /ws must 401: got %d", res.StatusCode)
	}
	if res := get("/api/version", nil); res.StatusCode != 200 {
		t.Errorf("exempt /api/version: got %d", res.StatusCode)
	}
	if len(touched) == 0 || touched[0] != "acc-ui" {
		t.Errorf("touchLastUsed not invoked for authenticated request: %v", touched)
	}
}
