// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Port of src/hydra/bearer-resolver.ts: opaque token -> principal via RFC
// 7662 introspection, with a positive-only TTL cache (an ephemeral.Store —
// the Node comments explain why negative results are never cached).
package hydra

import (
	"context"
	"strings"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/ephemeral"
)

// Principal is what the bearer gate attaches to the request context
// (BearerPrincipal in bearer-resolver.ts).
type Principal struct {
	AccountID string
	Scopes    []string
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

const maxCacheEntries = 2048

// NewResolver builds the caching resolver. cacheTTL <= 0 disables caching
// (introspect every request), matching introspectionCacheTtlMs: 0.
func NewResolver(admin Introspector, cacheTTL time.Duration, clk clock.Clock) Resolver {
	var cache *ephemeral.Store[string, Principal]
	if cacheTTL > 0 {
		cache = ephemeral.New[string, Principal](cacheTTL, maxCacheEntries, clk)
	}

	return func(ctx context.Context, token string) *Principal {
		if cache != nil {
			if p, ok := cache.Get(token); ok {
				return &p
			}
		}

		ins, err := admin.Introspect(ctx, token)
		if err != nil {
			// Fail closed: an unreachable / erroring introspection endpoint
			// must not grant access. Transient failures are never cached.
			return nil
		}
		// Default-deny: only access tokens authorize a request — requiring
		// token_use == "access_token" stops a leaked refresh token (which
		// introspects active with the same sub+scope) being replayed as a
		// bearer.
		if !ins.Active || ins.Sub == "" || ins.TokenUse != "access_token" {
			return nil
		}
		p := Principal{AccountID: ins.Sub, Scopes: strings.Fields(ins.Scope)}
		// Cache ONLY valid principals — negative caching would let an
		// attacker spraying invalid tokens evict legitimate entries.
		if cache != nil {
			cache.Put(token, p)
		}
		return &p
	}
}
