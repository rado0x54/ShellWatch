// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// hydra.devProxyUpstream: the single-origin dev mode forwards Hydra's public
// surface (and nothing else) without a bearer token, so strict OAuth
// discovery (RFC 8414 §3.3) works against one origin in local dev.
package httpserver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/config"
)

func devProxyServer(t *testing.T, upstream string) *httptest.Server {
	t.Helper()
	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = externalURL // single-origin: publicUrl == externalUrl
	cfg.Hydra.DevProxyUpstream = upstream
	handler := New(Params{
		Config:    cfg,
		Resolve:   auth.Resolver(func(context.Context, string) *auth.Principal { return nil }),
		StaticFS:  os.DirFS(t.TempDir()),
		BuildInfo: buildinfo.Info{},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

func TestHydraDevProxyForwardsPublicSurface(t *testing.T) {
	type hit struct{ method, path, forwardedHost string }
	var last hit
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last = hit{method: r.Method, path: r.URL.Path, forwardedHost: r.Header.Get("X-Forwarded-Host")}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"from":"hydra"}`))
	}))
	t.Cleanup(upstream.Close)
	ts := devProxyServer(t, upstream.URL)

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/.well-known/openid-configuration"},
		{http.MethodGet, "/.well-known/jwks.json"},
		{http.MethodGet, "/userinfo"},
		{http.MethodPost, "/oauth2/token"},
		{http.MethodGet, "/oauth2/auth"},
	} {
		req, _ := http.NewRequest(tc.method, ts.URL+tc.path, nil) // no bearer: public surface
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 || !strings.Contains(string(body), `"from":"hydra"`) {
			t.Fatalf("%s %s: status=%d body=%q (not proxied)", tc.method, tc.path, res.StatusCode, body)
		}
		if last.path != tc.path || last.method != tc.method {
			t.Fatalf("%s %s: upstream saw %s %s", tc.method, tc.path, last.method, last.path)
		}
		if last.forwardedHost == "" {
			t.Errorf("%s: X-Forwarded-Host not set for upstream", tc.path)
		}
	}

	// ShellWatch's own discovery docs are NOT proxied: the blended
	// authorization-server metadata stays ours.
	res, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if strings.Contains(string(body), `"from":"hydra"`) {
		t.Fatal("blended AS metadata was proxied to Hydra")
	}
	if !strings.Contains(string(body), `"registration_endpoint"`) {
		t.Fatalf("blended AS metadata missing: %q", body)
	}
	// Single-origin consistency (RFC 8414 §3.3): issuer == the origin the doc
	// is served from.
	if !strings.Contains(string(body), `"issuer":"`+externalURL+`"`) {
		t.Fatalf("blended issuer is not the shared origin: %q", body)
	}
}

func TestHydraDevProxyOffByDefault(t *testing.T) {
	ts := devProxyServer(t, "")
	res, err := http.Post(ts.URL+"/oauth2/token", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode == http.StatusBadGateway || res.StatusCode == http.StatusOK {
		t.Fatalf("/oauth2/token answered %d with no devProxyUpstream configured", res.StatusCode)
	}
}
