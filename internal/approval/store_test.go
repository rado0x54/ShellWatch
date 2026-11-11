// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package approval

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/signing"
)

func newStore(t *testing.T) (*Store, *clock.Fake) {
	t.Helper()
	clk := clock.NewFake(time.Unix(1000, 0))
	var n int
	return NewStore(clk, func() string { n++; return "act" }), clk
}

func TestStoreResolveEmitsApproved(t *testing.T) {
	s, _ := newStore(t)
	var outcome Outcome
	s.OnResolved(func(e ResolvedEvent) { outcome = e.Outcome })
	resolved := make(chan signing.SignResponse, 1)
	a := s.Create(CreateParams{AccountID: "acc", Type: TypeWebAuthnSign,
		ResolveSign: func(r signing.SignResponse) { resolved <- r }})

	if !s.ResolveSign(a.ID, signing.SignResponse{ClientDataJSON: []byte("x")}).Won {
		t.Fatal("resolve failed")
	}
	if string((<-resolved).ClientDataJSON) != "x" {
		t.Fatal("resolve closure not called")
	}
	if outcome != OutcomeApproved {
		t.Fatalf("outcome: %s", outcome)
	}
	// Second resolve is a no-op; the loser learns the asserted status.
	if res := s.ResolveSign(a.ID, signing.SignResponse{}); res.Won || !res.Found || res.Status != StatusCompleted {
		t.Fatalf("double resolve: %+v, want lost claim on completed", res)
	}
}

func TestStoreExpireRejectsAndEmits(t *testing.T) {
	s, clk := newStore(t)
	var outcome Outcome
	s.OnResolved(func(e ResolvedEvent) { outcome = e.Outcome })
	rejected := make(chan error, 1)
	a := s.Create(CreateParams{AccountID: "acc", Type: TypeWebAuthnSign,
		Reject: func(err error) { rejected <- err }})

	clk.Advance(ActionTTL + time.Second)
	s.Sweep()
	if err := <-rejected; err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
	if outcome != OutcomeExpired {
		t.Fatalf("outcome: %s", outcome)
	}
	if s.Get(a.ID).Status != StatusExpired {
		t.Fatal("status not expired")
	}
}

// Deliberate divergence from Node: cancel MUST reject. Node can drop the
// resolver (the pending promise is garbage-collected); in Go a forwarding
// awaiter blocks on the broker with context.Background(), so a cancel that
// never rejects strands that goroutine forever.
func TestStoreCancelForConnectionRejectsWithCancelled(t *testing.T) {
	s, _ := newStore(t)
	var outcome Outcome
	var cancelReason string
	s.OnResolved(func(e ResolvedEvent) { outcome = e.Outcome; cancelReason = e.CancelReason })
	var rejectedWith error
	s.Create(CreateParams{AccountID: "acc", Type: TypeWebAuthnSign, ConnectionID: "c1",
		Reject: func(err error) { rejectedWith = err }})

	if cancelled := s.CancelForConnection("c1", "connection closed"); len(cancelled) != 1 {
		t.Fatalf("cancelled %d", len(cancelled))
	}
	if rejectedWith != ErrCancelled {
		t.Errorf("reject: got %v, want ErrCancelled", rejectedWith)
	}
	if outcome != OutcomeCancelled || cancelReason != "connection closed" {
		t.Fatalf("outcome %s reason %q", outcome, cancelReason)
	}
}

// The leak scenario end-to-end: an awaiter blocked with a non-cancellable
// context (terminal-path agent forwarding) must be released by a
// connection-cancel, not stranded until process exit.
func TestBrokerCancelUnblocksBackgroundAwaiter(t *testing.T) {
	s, _ := newStore(t)
	b := NewBroker(s, func() string { return "https://sw.example" })

	done := make(chan error, 1)
	go func() {
		_, err := b.RequestKeyApproval(context.Background(), KeyApproval{
			AccountID: "acc", KeyLabel: "key", KeyFingerprint: "SHA256:fp", ConnectionID: "c1",
			Context: Context{Source: "agent-forwarding"},
		})
		done <- err
	}()
	// Wait for the action to exist, then cancel the connection.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(s.CancelForConnection("c1", "SSH connection closed")) == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case err := <-done:
		if err != ErrCancelled {
			t.Fatalf("awaiter returned %v, want ErrCancelled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("awaiter still blocked after connection cancel — goroutine leak")
	}
}

// Regression: the pending->terminal transition must be claimed under the
// store lock. Concurrent resolve + deny (double-submit, two tabs on
// /sign/:id, or a resolve racing the TTL sweep) used to both see "pending"
// and both fire their callback — the broker's channels are 1-buffered and
// consumed once, so the second send blocked its HTTP handler forever.
func TestStoreConcurrentResolveDenyFiresOnce(t *testing.T) {
	for i := 0; i < 100; i++ {
		s, _ := newStore(t)
		var resolved, rejected, events, wins atomic.Int32
		s.OnResolved(func(ResolvedEvent) { events.Add(1) })
		a := s.Create(CreateParams{AccountID: "acc", Type: TypeKeyApprove,
			ResolveKey: func() { resolved.Add(1) },
			Reject:     func(error) { rejected.Add(1) },
		})

		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			approve := j%2 == 0
			wg.Add(1)
			go func() {
				defer wg.Done()
				if approve {
					if s.ResolveKey(a.ID).Won {
						wins.Add(1)
					}
				} else if s.Deny(a.ID).Won {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("round %d: %d resolvers won, want exactly 1", i, wins.Load())
		}
		if got := resolved.Load() + rejected.Load(); got != 1 {
			t.Fatalf("round %d: %d callbacks fired, want exactly 1", i, got)
		}
		if events.Load() != 1 {
			t.Fatalf("round %d: %d resolved events, want exactly 1", i, events.Load())
		}
	}
}

// A type-mismatched resolve must not claim the action: the real resolver of
// the right kind still wins afterwards.
func TestStoreResolveTypeMismatchDoesNotClaim(t *testing.T) {
	s, _ := newStore(t)
	a := s.Create(CreateParams{AccountID: "acc", Type: TypeWebAuthnSign,
		ResolveSign: func(signing.SignResponse) {}})
	if res := s.ResolveKey(a.ID); res.Won || res.Found {
		t.Fatalf("key-approve resolve on a webauthn-sign action: %+v, want not found", res)
	}
	if !s.ResolveSign(a.ID, signing.SignResponse{}).Won {
		t.Fatal("action must still be pending after the mismatched resolve")
	}
}

// Deny is idempotent and losers always learn the store-asserted state: a
// second deny reports denied (not an error), a deny after a resolve reports
// completed, and a deny after the sweep reports not-found — never "resolved".
func TestStoreClaimResultsReportAssertedState(t *testing.T) {
	clk := clock.NewFake(time.Unix(1000, 0))
	var n atomic.Int32
	s := NewStore(clk, func() string { return fmt.Sprintf("act-%d", n.Add(1)) })

	a := s.Create(CreateParams{AccountID: "acc", Type: TypeKeyApprove, ResolveKey: func() {}, Reject: func(error) {}})
	if res := s.Deny(a.ID); !res.Won {
		t.Fatalf("first deny: %+v", res)
	}
	if res := s.Deny(a.ID); res.Won || !res.Found || res.Status != StatusDenied {
		t.Fatalf("deny of denied: %+v, want lost claim on denied", res)
	}

	b := s.Create(CreateParams{AccountID: "acc", Type: TypeKeyApprove, ResolveKey: func() {}, Reject: func(error) {}})
	if !s.ResolveKey(b.ID).Won {
		t.Fatal("resolve failed")
	}
	if res := s.Deny(b.ID); res.Won || !res.Found || res.Status != StatusCompleted {
		t.Fatalf("deny of completed: %+v, want lost claim on completed", res)
	}

	// Push both past expiry + grace so the sweep deletes them.
	clk.Advance(ActionTTL + cleanupGrace + time.Second)
	s.Sweep()
	if res := s.Deny(a.ID); res.Won || res.Found {
		t.Fatalf("deny of swept: %+v, want not found", res)
	}
}

// The claim path enforces the deadline itself: between ExpiresAt and the next
// sweep tick an action is still pending in memory, but no resolve (or deny)
// may claim it — the claim performs the expiry, rejects the waiter, and emits
// the expired event exactly once, and the later sweep doesn't double-fire.
func TestStoreClaimOnExpiredActionLosesAndExpires(t *testing.T) {
	clk := clock.NewFake(time.Unix(1000, 0))
	s := NewStore(clk, func() string { return "act" })
	var events, rejects atomic.Int32
	s.OnResolved(func(ResolvedEvent) { events.Add(1) })
	a := s.Create(CreateParams{
		AccountID: "acc", Type: TypeKeyApprove,
		ResolveKey: func() { t.Error("resolve closure fired for an expired action") },
		Reject:     func(error) { rejects.Add(1) },
	})

	clk.Advance(ActionTTL + time.Second) // past the deadline, no sweep yet

	if res := s.ResolveKey(a.ID); res.Won || !res.Found || res.Status != StatusExpired {
		t.Fatalf("resolve past deadline: %+v, want lost claim on expired", res)
	}
	if res := s.Deny(a.ID); res.Won || res.Status != StatusExpired {
		t.Fatalf("deny past deadline: %+v, want lost claim on expired", res)
	}
	s.Sweep() // must not double-fire: the claim already expired the action
	if rejects.Load() != 1 {
		t.Fatalf("reject fired %d times, want exactly 1", rejects.Load())
	}
	if events.Load() != 1 {
		t.Fatalf("resolved events fired %d times, want exactly 1", events.Load())
	}
}
