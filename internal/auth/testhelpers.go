// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package auth

import (
	"context"
	"net/http"
)

// ContextWithPrincipal returns ctx carrying p — the value the gate sets and
// PrincipalFrom reads. Exported so packages that mount authenticated handlers
// can inject a principal in tests without a live Hydra.
func ContextWithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// WithPrincipal wraps h so every request carries p (test helper for surfaces
// that read PrincipalFrom, e.g. the WS hub and agent proxy).
func WithPrincipal(h http.Handler, p Principal) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(ContextWithPrincipal(r.Context(), p)))
	})
}
