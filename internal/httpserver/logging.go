// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Request-logging middleware: one structured slog line per HTTP request with
// method, path, status, and duration. A passing /health probe logs at Debug.
// 4xx/5xx log at Warn so server-side
// problems (a failed SSH connect surfaces as a 400 here, an auth failure as
// 401) are visible in stdout / the log file instead of only in the response
// body. Outermost in the chain so it captures the final status.
package httpserver

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/rado0x54/shellwatch/internal/clock"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController reach hijack/flush for the WS + streaming
// handlers wrapped below.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// transferPathPrefix is the file-transfer link route (#263). The path segment
// after it is a bearer credential and must never reach a log line.
const transferPathPrefix = "/api/transfers/"

// Passkey-invite links carry the invite token in the path: the API lookup
// (/api/passkey-invite/{token}) and the SPA page (/passkey-invite/{token}).
// The register endpoints under the API prefix carry it in the body instead.
const (
	inviteAPIPrefix  = "/api/passkey-invite/"
	invitePagePrefix = "/passkey-invite/"
)

// redactPath hides credentials carried in the URL path.
func redactPath(path string) string {
	switch {
	case strings.HasPrefix(path, transferPathPrefix):
		return transferPathPrefix + "***"
	case strings.HasPrefix(path, inviteAPIPrefix):
		if rest := path[len(inviteAPIPrefix):]; rest == "register" || strings.HasPrefix(rest, "register/") {
			return path
		}
		return inviteAPIPrefix + "***"
	case strings.HasPrefix(path, invitePagePrefix):
		return invitePagePrefix + "***"
	}
	return path
}

// healthPath is polled by the container healthcheck every few seconds; a
// successful probe logs at debug so it does not drown the log.
const healthPath = "/health"

func requestLogger(clk clock.Clock) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := clk.Now()
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			if rec.status == 0 {
				rec.status = http.StatusOK
			}
			level := slog.LevelInfo
			if r.URL.Path == healthPath && rec.status < 400 {
				level = slog.LevelDebug
			} else if rec.status >= 500 {
				level = slog.LevelError
			} else if rec.status >= 400 {
				level = slog.LevelWarn
			}
			slog.LogAttrs(r.Context(), level, "http",
				slog.String("method", r.Method),
				slog.String("path", redactPath(r.URL.Path)),
				slog.Int("status", rec.status),
				slog.Duration("dur", clk.Now().Sub(start)),
			)
		})
	}
}
