// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// H9/H10 middleware behavior: rate limits on the unauthenticated surfaces and
// CORS preflight passing without a bearer token.
package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/config"
)

func middlewareServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	cfg.Security.RateLimit.SelfRegister = config.RateLimitRule{Max: 2, WindowMinutes: 15}
	resolve := auth.Resolver(func(context.Context, string) *auth.Principal { return nil })
	handler := New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

func TestRateLimitReturns429AfterMax(t *testing.T) {
	ts := middlewareServer(t)
	url := ts.URL + "/api/auth/register/options"
	var last *http.Response
	for i := 0; i < 3; i++ {
		res, err := http.Post(url, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		last = res
		if i < 2 && res.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d already limited", i+1)
		}
	}
	if last.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("3rd request: got %d, want 429", last.StatusCode)
	}
	if ra := last.Header.Get("Retry-After"); ra == "" {
		t.Error("429 missing Retry-After")
	}
	if lim := last.Header.Get("X-RateLimit-Limit"); lim != "2" {
		t.Errorf("X-RateLimit-Limit = %q, want 2", lim)
	}
}

func TestUnlimitedRouteUnaffected(t *testing.T) {
	ts := middlewareServer(t)
	for i := 0; i < 5; i++ {
		res, err := http.Get(ts.URL + "/health")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 200 {
			t.Fatalf("health: got %d", res.StatusCode)
		}
	}
}

func TestCORSPreflightBypassesBearerGate(t *testing.T) {
	ts := middlewareServer(t)
	req, _ := http.NewRequest(http.MethodOptions, ts.URL+"/api/sessions", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "authorization,content-type")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight: got %d, want 204", res.StatusCode)
	}
	if got := res.Header.Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("allow-origin = %q", got)
	}
	if got := res.Header.Get("Access-Control-Allow-Headers"); got != "authorization,content-type" {
		t.Errorf("allow-headers = %q", got)
	}
	if !strings.Contains(res.Header.Get("Access-Control-Allow-Methods"), "POST") {
		t.Errorf("allow-methods = %q", res.Header.Get("Access-Control-Allow-Methods"))
	}
}

func TestCORSReflectsOriginOnNormalRequests(t *testing.T) {
	ts := middlewareServer(t)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/health", nil)
	req.Header.Set("Origin", "https://app.example.com")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if got := res.Header.Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("allow-origin = %q", got)
	}
}
