// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package auth

import "context"

// Principal is the authenticated identity the bearer gate attaches to a
// request (BearerPrincipal in bearer-resolver.ts). It lives in auth (not
// hydra) so lower-level packages can depend on it without importing the
// Hydra glue — hydra.NewResolver produces one.
type Principal struct {
	AccountID string
	// ClientID is the OAuth client the token was issued to (introspection
	// client_id). Terminal-session ownership on the MCP surface is scoped to
	// (AccountID, ClientID) — see internal/agent (#243).
	ClientID string
	Scopes   []string
}

func (p Principal) HasScope(s string) bool {
	for _, sc := range p.Scopes {
		if sc == s {
			return true
		}
	}
	return false
}

// Resolver maps a bearer token to a principal, or nil (fail closed).
type Resolver func(ctx context.Context, token string) *Principal
