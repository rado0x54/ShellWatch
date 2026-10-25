// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Port of src/hydra/bearer-resolver.ts: opaque token -> principal via RFC
// 7662 introspection, with a positive-only TTL cache (an ephemeral.Store —
// the Node comments explain why negative results are never cached).
package hydra

import (
	"context"
	"strings"
	"time"

	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/ephemeral"
)

const maxCacheEntries = 2048

// NewResolver builds the caching resolver (returns an auth.Resolver, since
// Principal is an auth concept). cacheTTL <= 0 disables caching (introspect
// every request), matching introspectionCacheTtlMs: 0.
func NewResolver(admin Introspector, cacheTTL time.Duration, clk clock.Clock) auth.Resolver {
	var cache *ephemeral.Store[string, auth.Principal]
	if cacheTTL > 0 {
		cache = ephemeral.New[string, auth.Principal](cacheTTL, maxCacheEntries, clk)
	}

	return func(ctx context.Context, token string) *auth.Principal {
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
		p := auth.Principal{AccountID: ins.Sub, Scopes: strings.Fields(ins.Scope)}
		// Cache ONLY valid principals — negative caching would let an
		// attacker spraying invalid tokens evict legitimate entries.
		if cache != nil {
			cache.Put(token, p)
		}
		return &p
	}
}
