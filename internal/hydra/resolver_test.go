// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Port of the behavioral contract in src/hydra/bearer-resolver.test.ts:
// access-token-only, fail-closed, positive-only caching with TTL.
package hydra

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
)

type fakeIntrospector struct {
	calls int
	fn    func(token string) (Introspection, error)
}

func (f *fakeIntrospector) Introspect(_ context.Context, token string) (Introspection, error) {
	f.calls++
	return f.fn(token)
}

func access(sub, scope string) Introspection {
	return Introspection{Active: true, Sub: sub, Scope: scope, TokenUse: "access_token"}
}

func TestResolverAcceptsOnlyActiveAccessTokens(t *testing.T) {
	fake := &fakeIntrospector{fn: func(token string) (Introspection, error) {
		switch token {
		case "good":
			return access("acc-1", "ui mcp"), nil
		case "refresh":
			return Introspection{Active: true, Sub: "acc-1", Scope: "ui", TokenUse: "refresh_token"}, nil
		case "inactive":
			return Introspection{Active: false}, nil
		case "nosub":
			return Introspection{Active: true, TokenUse: "access_token"}, nil
		}
		return Introspection{}, errors.New("boom")
	}}
	r := NewResolver(fake, 0, clock.Real{})
	ctx := context.Background()

	p := r(ctx, "good")
	if p == nil || p.AccountID != "acc-1" || !p.HasScope("mcp") || p.HasScope("agent") {
		t.Fatalf("good token: %+v", p)
	}
	// A leaked refresh token must NOT work as a bearer.
	if r(ctx, "refresh") != nil {
		t.Fatal("refresh token accepted")
	}
	if r(ctx, "inactive") != nil || r(ctx, "nosub") != nil {
		t.Fatal("inactive/subless token accepted")
	}
	// Introspection errors fail closed.
	if r(ctx, "error") != nil {
		t.Fatal("introspection error must fail closed")
	}
}

func TestResolverCachesPositiveOnlyWithTTL(t *testing.T) {
	clk := clock.NewFake(time.Unix(1000, 0))
	fake := &fakeIntrospector{fn: func(token string) (Introspection, error) {
		if token == "good" {
			return access("acc-1", "ui"), nil
		}
		return Introspection{Active: false}, nil
	}}
	r := NewResolver(fake, time.Minute, clk)
	ctx := context.Background()

	r(ctx, "good")
	r(ctx, "good")
	if fake.calls != 1 {
		t.Fatalf("positive result not cached: %d introspections", fake.calls)
	}
	// Negative results are never cached (cache-poisoning resistance).
	r(ctx, "bad")
	r(ctx, "bad")
	if fake.calls != 3 {
		t.Fatalf("negative result was cached: %d introspections", fake.calls)
	}
	// TTL expiry bounds revocation latency: re-introspect after the window.
	clk.Advance(61 * time.Second)
	r(ctx, "good")
	if fake.calls != 4 {
		t.Fatalf("cache did not expire: %d introspections", fake.calls)
	}
}
