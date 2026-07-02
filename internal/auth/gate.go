// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package auth is the single bearer gate (port of
// src/server/auth/bearer-gate.ts): every authenticated surface presents a
// Hydra opaque access token, introspected via the resolver, authorized by
// scope per path. Exempt lists, WS-subprotocol token extraction, and the
// RFC 6750/9728 WWW-Authenticate shapes are byte-compatible with Node
// (pinned by the err-401 goldens).
package auth

import (
	"context"
	"net/http"
	"strings"
)

const (
	UIScope    = "ui"
	McpScope   = "mcp"
	AgentScope = "agent"

	// WSBearerSubprotocol is the sentinel the browser SPA offers alongside
	// the token (["shellwatch.bearer", <token>]) — browsers can't set an
	// Authorization header on a WS handshake. The server negotiates the
	// sentinel, never echoing the token.
	WSBearerSubprotocol = "shellwatch.bearer"

	WellKnownProtectedResource = "/.well-known/oauth-protected-resource"
)

// BearerPaths maps the externally-discoverable scopes to the paths they
// guard (BEARER_PATHS in bearer-gate.ts).
var BearerPaths = map[string]string{
	McpScope:   "/mcp",
	AgentScope: "/agent-proxy",
}

// ResourceMetadataPath returns the RFC 9728 discovery path for a scope.
func ResourceMetadataPath(scope string) string {
	return WellKnownProtectedResource + BearerPaths[scope]
}

// Exact paths that never require a token.
var exemptExact = map[string]bool{
	"/health":        true,
	"/api/version":   true,
	"/config.js":     true,
	"/manifest.json": true,
	// Anonymous onboarding / bootstrap (passkey registration has no token yet).
	"/api/auth/register":         true,
	"/api/auth/register/options": true,
	"/api/auth/passkey-status":   true,
}

// Path prefixes that never require a token (see bearer-gate.ts for why).
var exemptPrefixes = []string{
	"/api/hydra/",
	"/api/passkey-invite/",
	"/passkey-invite/",
	"/.well-known/",
	"/_app/",
}

type principalKey struct{}

// PrincipalFrom returns the authenticated principal, if the gate set one.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

type GateParams struct {
	Resolve Resolver
	// ExternalURL is read at request time (test helpers pin it after boot).
	ExternalURL func() string
	// AgentProxyEnabled gates the /agent-proxy path (unregistered otherwise).
	AgentProxyEnabled bool
	// TouchLastUsed records account activity on every authenticated request
	// (batched write-behind; see store.LastUsedFlusher).
	TouchLastUsed func(accountID string)
}

// Gate returns the chi/net-http middleware.
func Gate(p GateParams) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			if isExempt(path) {
				next.ServeHTTP(w, r)
				return
			}
			scope := requiredScope(path, p.AgentProxyEnabled)
			if scope == "" {
				// SPA HTML routes / static — pass through; the SPA gates
				// itself client-side.
				next.ServeHTTP(w, r)
				return
			}

			token := extractToken(r, path)
			if token == "" {
				send401(w, p, scope, "Access token required", "missing")
				return
			}
			principal := p.Resolve(r.Context(), token)
			if principal == nil {
				send401(w, p, scope, "Invalid or expired access token", "invalid")
				return
			}
			// Authorization is by SCOPE only; audience is deliberately not
			// checked (see bearer-gate.ts for the rationale).
			if !principal.HasScope(scope) {
				send401(w, p, scope, "Token lacks '"+scope+"' scope", "scope")
				return
			}

			if p.TouchLastUsed != nil {
				p.TouchLastUsed(principal.AccountID)
			}
			ctx := context.WithValue(r.Context(), principalKey{}, *principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractToken reads Authorization: Bearer, with the Sec-WebSocket-Protocol
// fallback scoped to /ws only (browsers can't set WS handshake headers; a
// subprotocol-smuggled token must not work anywhere else).
func extractToken(r *http.Request, path string) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return auth[len("Bearer "):]
	}
	if path == "/ws" {
		if proto := r.Header.Get("Sec-Websocket-Protocol"); proto != "" {
			parts := strings.Split(proto, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			if len(parts) >= 2 && parts[0] == WSBearerSubprotocol && parts[1] != "" {
				return parts[1]
			}
		}
	}
	return ""
}

func isExempt(path string) bool {
	if exemptExact[path] {
		return true
	}
	for _, p := range exemptPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// requiredScope: which scope (if any) guards this path ("" = unprotected).
func requiredScope(path string, agentProxyEnabled bool) string {
	switch {
	case path == "/mcp" || strings.HasPrefix(path, "/mcp/"):
		return McpScope
	case agentProxyEnabled && (path == "/agent-proxy" || strings.HasPrefix(path, "/agent-proxy/")):
		return AgentScope
	case path == "/ws":
		return UIScope
	case strings.HasPrefix(path, "/api/"):
		return UIScope
	}
	return ""
}

func send401(w http.ResponseWriter, p GateParams, scope, message, kind string) {
	status := http.StatusUnauthorized
	if kind == "scope" {
		status = http.StatusForbidden
	}
	parts := []string{`Bearer realm="shellwatch"`}
	// RFC 9728 discovery hint only for the externally-discoverable resources.
	if scope == McpScope || scope == AgentScope {
		ext := strings.TrimRight(p.ExternalURL(), "/")
		parts = append(parts, `resource_metadata="`+ext+ResourceMetadataPath(scope)+`"`)
	}
	if kind == "invalid" {
		parts = append(parts, `error="invalid_token"`)
	}
	if kind == "scope" {
		parts = append(parts, `error="insufficient_scope"`)
	}
	w.Header().Set("WWW-Authenticate", strings.Join(parts, ", "))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + message + `"}`))
}
