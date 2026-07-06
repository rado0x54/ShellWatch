// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package approval

import (
	"context"
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

	if !s.ResolveSign(a.ID, signing.SignResponse{ClientDataJSON: []byte("x")}) {
		t.Fatal("resolve failed")
	}
	if string((<-resolved).ClientDataJSON) != "x" {
		t.Fatal("resolve closure not called")
	}
	if outcome != OutcomeApproved {
		t.Fatalf("outcome: %s", outcome)
	}
	// Second resolve is a no-op (already completed -> 409 territory).
	if s.ResolveSign(a.ID, signing.SignResponse{}) {
		t.Fatal("double resolve should fail")
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
		done <- b.RequestKeyApproval(context.Background(), "acc", "key", "SHA256:fp", "c1", Context{Source: "agent-forwarding"})
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
