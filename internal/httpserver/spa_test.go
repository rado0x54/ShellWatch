// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// SPA serving: static files, the index.html fallback for client routes, and
// the caching contract (content-hashed _app/immutable/ assets cached forever,
// everything else revalidated — embedded files have no modtime, so without
// explicit headers every reload would re-download the bundle).
package httpserver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/config"
)

func TestSPACacheHeaders(t *testing.T) {
	staticFS := fstest.MapFS{
		"index.html":                      {Data: []byte("<html>app</html>")},
		"favicon.png":                     {Data: []byte("png")},
		"service-worker.js":               {Data: []byte("sw")},
		"_app/immutable/chunks/x-abc.js":  {Data: []byte("js")},
		"_app/immutable/assets/y-def.css": {Data: []byte("css")},
	}
	handler := spaHandler(staticFS)

	cases := []struct {
		path       string
		wantStatus int
		wantCache  string
	}{
		{"/_app/immutable/chunks/x-abc.js", 200, "public, max-age=31536000, immutable"},
		{"/_app/immutable/assets/y-def.css", 200, "public, max-age=31536000, immutable"},
		{"/favicon.png", 200, "no-cache"},
		{"/service-worker.js", 200, "no-cache"},
		// Go's file server canonicalizes /index.html to / (301); the redirect
		// target is the fallback below, which answers no-cache.
		{"/index.html", 301, "no-cache"},
		// Directories must NOT get the file server's auto-generated listing
		// (least of all a one-year-immutable one): they fall back to the SPA.
		{"/_app/immutable", 200, "no-cache"},
		{"/_app/immutable/chunks", 200, "no-cache"},
		// Client-side routes fall back to index.html and must revalidate too.
		{"/settings/endpoints", 200, "no-cache"},
		{"/", 200, "no-cache"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest("GET", tc.path, nil))
		if rec.Code != tc.wantStatus {
			t.Errorf("%s: status %d, want %d", tc.path, rec.Code, tc.wantStatus)
		}
		if got := rec.Header().Get("Cache-Control"); got != tc.wantCache {
			t.Errorf("%s: Cache-Control %q, want %q", tc.path, got, tc.wantCache)
		}
	}

	// The API / discovery 404 body is part of the wire contract, not the
	// SPA's caching: neither prefix ever falls back to index.html.
	for _, path := range []string{"/api/nope", "/.well-known/nope"} {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 404 || rec.Body.String() != `{"error":"Not found"}` {
			t.Errorf("%s fallback: %d %q", path, rec.Code, rec.Body.String())
		}
	}
}

// With the agent proxy off, its feature-gated discovery documents are absent:
// a real JSON 404 through the full stack, not the SPA's index.html.
func TestAgentDiscoveryRoutes404WhenProxyDisabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	cfg.AgentSocket.ProxyEnabled = false
	deny := auth.Resolver(func(context.Context, string) *auth.Principal { return nil })
	ts := httptest.NewServer(New(Params{
		Config:    cfg,
		Resolve:   deny,
		StaticFS:  fstest.MapFS{"index.html": {Data: []byte("<html>app</html>")}},
		BuildInfo: buildinfo.Info{},
	}))
	t.Cleanup(ts.Close)

	for _, path := range []string{
		"/.well-known/oauth-protected-resource/agent-proxy",
		"/.well-known/shellwatch-agent-client.json",
	} {
		res, err := ts.Client().Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusNotFound || string(body) != `{"error":"Not found"}` {
			t.Errorf("%s: %d %q, want 404 {\"error\":\"Not found\"}", path, res.StatusCode, body)
		}
		if ct := res.Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
			t.Errorf("%s: Content-Type %q", path, ct)
		}
	}
}
