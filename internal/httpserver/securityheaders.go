// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Baseline security response headers on every response (SPA HTML, static
// assets, API JSON, Hydra login/consent pages, errors). The UI is never meant
// to be framed: the admin surface has one-click destructive actions that are
// not WebAuthn-gated, so framing would enable clickjacking.
package httpserver

import (
	"net/http"
	"strings"
)

// hstsValue is sent only when the public origin is HTTPS. ShellWatch never
// terminates TLS itself (a reverse proxy does), so the configured external
// URL — not r.TLS — decides; browsers ignore HSTS on plain-HTTP responses
// anyway. No includeSubDomains: sibling hosts aren't ours to pin.
const hstsValue = "max-age=31536000"

func securityHeaders(externalURL func() string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Frame-Options", "DENY")
			// frame-ancestors is the modern equivalent of X-Frame-Options.
			// Deliberately the only directive: a full CSP is a separate change.
			h.Set("Content-Security-Policy", "frame-ancestors 'none'")
			h.Set("X-Content-Type-Options", "nosniff")
			// Nothing reads Referer, and the login/consent/WebAuthn steps use
			// fetch (whose CORS-mode Origin header is unaffected by this policy).
			h.Set("Referrer-Policy", "no-referrer")
			if strings.HasPrefix(strings.ToLower(externalURL()), "https://") {
				h.Set("Strict-Transport-Security", hstsValue)
			}
			next.ServeHTTP(w, r)
		})
	}
}
