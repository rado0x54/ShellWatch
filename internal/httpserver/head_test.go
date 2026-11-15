// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// HEAD on GET routes (RFC 9110 §9.3.2) through the full handler stack.
package httpserver

import (
	"io"
	"net/http"
	"testing"
)

func TestHeadMirrorsGet(t *testing.T) {
	ts := testServer(t)

	do := func(method, path string) (*http.Response, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res, body
	}

	for _, path := range []string{
		"/health",
		"/api/version",
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-protected-resource/agent-proxy",
		"/.well-known/shellwatch-agent-client.json",
		// JSON 404, not the SPA.
		"/.well-known/nope",
		// Gated: 401 for both; HEAD must not bypass the bearer gate.
		"/api/endpoints",
	} {
		get, _ := do(http.MethodGet, path)
		head, body := do(http.MethodHead, path)
		if head.StatusCode != get.StatusCode {
			t.Errorf("%s: HEAD %d, GET %d", path, head.StatusCode, get.StatusCode)
		}
		if len(body) != 0 {
			t.Errorf("%s: HEAD returned a %d-byte body", path, len(body))
		}
		for _, h := range []string{"Content-Type", "Cache-Control", "Www-Authenticate"} {
			if head.Header.Get(h) != get.Header.Get(h) {
				t.Errorf("%s: %s HEAD %q, GET %q", path, h, head.Header.Get(h), get.Header.Get(h))
			}
		}
	}

	// The case that prompted this: `curl -I` on the agent's CIMD document.
	if res, _ := do(http.MethodHead, "/.well-known/shellwatch-agent-client.json"); res.StatusCode != http.StatusOK {
		t.Errorf("HEAD agent document: %d, want 200", res.StatusCode)
	}
	if res, _ := do(http.MethodHead, "/api/endpoints"); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("HEAD gated route: %d, want 401", res.StatusCode)
	}
}
