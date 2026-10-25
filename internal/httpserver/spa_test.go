// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// SPA serving: static files, the index.html fallback for client routes, and
// the caching contract (content-hashed _app/immutable/ assets cached forever,
// everything else revalidated — embedded files have no modtime, so without
// explicit headers every reload would re-download the bundle).
package httpserver

import (
	"net/http/httptest"
	"testing"
	"testing/fstest"
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

	// The API 404 body is part of the wire contract, not the SPA's caching.
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest("GET", "/api/nope", nil))
	if rec.Code != 404 || rec.Body.String() != `{"error":"Not found"}` {
		t.Errorf("api fallback: %d %q", rec.Code, rec.Body.String())
	}
}
