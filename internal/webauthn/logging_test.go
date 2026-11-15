// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package webauthn

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A 500 keeps its body generic but logs the underlying cause.
func TestWriteInternalLogsCause(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	rec := httptest.NewRecorder()
	writeInternal(rec, httptest.NewRequest(http.MethodGet, "/api/auth/passkey-status", nil),
		errors.New("database is locked"))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "database is locked") || !strings.Contains(body, "internal error") {
		t.Errorf("response body must stay generic, got %q", body)
	}
	logged := buf.String()
	for _, want := range []string{"level=ERROR", "webauthn: internal error", `err="database is locked"`} {
		if !strings.Contains(logged, want) {
			t.Errorf("log missing %q:\n%s", want, logged)
		}
	}
}
