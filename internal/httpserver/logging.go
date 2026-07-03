// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Request-logging middleware: one structured slog line per HTTP request with
// method, path, status, and duration. 4xx/5xx log at Warn so server-side
// problems (a failed SSH connect surfaces as a 400 here, an auth failure as
// 401) are visible in stdout / the log file instead of only in the response
// body. Outermost in the chain so it captures the final status.
package httpserver

import (
	"log/slog"
	"net/http"

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
			if rec.status >= 500 {
				level = slog.LevelError
			} else if rec.status >= 400 {
				level = slog.LevelWarn
			}
			slog.LogAttrs(r.Context(), level, "http",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", rec.status),
				slog.Duration("dur", clk.Now().Sub(start)),
			)
		})
	}
}
