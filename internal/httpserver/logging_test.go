// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package httpserver

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rado0x54/shellwatch/internal/clock"
)

func TestRedactPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/api/transfers/tok", "/api/transfers/***"},
		{"/api/passkey-invite/s3cr3t", "/api/passkey-invite/***"},
		{"/api/passkey-invite/register", "/api/passkey-invite/register"},
		{"/api/passkey-invite/register/options", "/api/passkey-invite/register/options"},
		{"/passkey-invite/s3cr3t", "/passkey-invite/***"},
		{"/api/endpoints/abc", "/api/endpoints/abc"},
	}
	for _, c := range cases {
		if got := redactPath(c.in); got != c.want {
			t.Errorf("redactPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRequestLoggerLevels(t *testing.T) {
	cases := []struct {
		path   string
		status int
		want   string // "" = not logged at info
	}{
		{"/health", http.StatusOK, ""},
		{"/health", http.StatusServiceUnavailable, "level=ERROR"},
		{"/api/endpoints", http.StatusOK, "level=INFO"},
		{"/api/endpoints", http.StatusNotFound, "level=WARN"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
		h := requestLogger(clock.Real{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, c.path, nil))
		slog.SetDefault(prev)

		logged := buf.String()
		if c.want == "" {
			if logged != "" {
				t.Errorf("%s %d: logged at info, want debug only:\n%s", c.path, c.status, logged)
			}
			continue
		}
		if !strings.Contains(logged, c.want) {
			t.Errorf("%s %d: want %s, got:\n%s", c.path, c.status, c.want, logged)
		}
	}
}
