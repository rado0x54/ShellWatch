// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package approval

import (
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

func TestStoreCancelForConnectionDoesNotReject(t *testing.T) {
	s, _ := newStore(t)
	var outcome Outcome
	var cancelReason string
	s.OnResolved(func(e ResolvedEvent) { outcome = e.Outcome; cancelReason = e.CancelReason })
	rejected := false
	s.Create(CreateParams{AccountID: "acc", Type: TypeWebAuthnSign, ConnectionID: "c1",
		Reject: func(error) { rejected = true }})

	if n := s.CancelForConnection("c1", "connection closed"); n != 1 {
		t.Fatalf("cancelled %d", n)
	}
	// The reject closure is NOT called on cancel (awaiter already gone), but
	// the audit outcome is "cancelled".
	if rejected {
		t.Error("reject should not be called on cancel")
	}
	if outcome != OutcomeCancelled || cancelReason != "connection closed" {
		t.Fatalf("outcome %s reason %q", outcome, cancelReason)
	}
}
