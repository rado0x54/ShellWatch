// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package apierr

import (
	"net/http/httptest"
	"testing"
)

// The exact bytes are the contract — handlers across five packages delegate
// here, so a change in encoding (key order, charset, trailing newline) would
// ripple across every error the server emits.
func TestEnvelopes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		render func(w *httptest.ResponseRecorder)
		status int
		body   string
	}{
		{"standard", func(w *httptest.ResponseRecorder) { Write(w, 404, "Session not found") },
			404, `{"error":"Session not found"}` + "\n"},
		{"status-200 body", func(w *httptest.ResponseRecorder) { Write(w, 200, "no_passkeys") },
			200, `{"error":"no_passkeys"}` + "\n"},
		{"step-up code", func(w *httptest.ResponseRecorder) {
			WriteCode(w, 401, "Step-up authentication required", "stepup_missing")
		},
			401, `{"code":"stepup_missing","error":"Step-up authentication required"}` + "\n"},
		{"oauth", func(w *httptest.ResponseRecorder) { WriteOAuth(w, 400, "invalid_scope", "scope must be a subset") },
			400, `{"error":"invalid_scope","error_description":"scope must be a subset"}` + "\n"},
	} {
		w := httptest.NewRecorder()
		tc.render(w)
		if w.Code != tc.status {
			t.Errorf("%s: status %d want %d", tc.name, w.Code, tc.status)
		}
		if got := w.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Errorf("%s: content-type %q", tc.name, got)
		}
		if w.Body.String() != tc.body {
			t.Errorf("%s: body %q want %q", tc.name, w.Body.String(), tc.body)
		}
	}
}
