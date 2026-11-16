// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package ticket

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// fakeSessions is a scripted Manager: Create blocks until the test answers,
// and the test injects status events directly.
type fakeSessions struct {
	mu      sync.Mutex
	sub     func(terminal.StatusEvent)
	creates chan terminal.Trigger
	answers chan error
	closed  []string
}

func (f *fakeSessions) Create(ctx context.Context, _ terminal.EndpointRef, _ string, tr terminal.Trigger) (*terminal.Session, error) {
	f.creates <- tr
	select {
	case err := <-f.answers:
		if err != nil {
			f.emit(tr.SessionID, terminal.StatusClosed, terminal.StatusOpening, terminal.CloseTransportError)
			return nil, err
		}
		f.emit(tr.SessionID, terminal.StatusOpen, terminal.StatusOpening, "")
		return &terminal.Session{SessionID: tr.SessionID}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *fakeSessions) Close(sessionID string, _ terminal.CloseReason) {
	f.mu.Lock()
	f.closed = append(f.closed, sessionID)
	f.mu.Unlock()
}

func (f *fakeSessions) SubscribeStatus(fn func(terminal.StatusEvent)) func() {
	f.sub = fn
	return func() {}
}

func (f *fakeSessions) emit(sid string, st, prev terminal.Status, reason terminal.CloseReason) {
	f.sub(terminal.StatusEvent{SessionID: sid, Status: st, Previous: prev, Reason: reason})
}

func (f *fakeSessions) closedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.closed...)
}

type pubLog struct {
	mu     sync.Mutex
	states []string
}

func (p *pubLog) GuestStatus(_ string, st Status) { p.add(st.State) }
func (p *pubLog) GuestOpen(string, string)        {}
func (p *pubLog) GuestClose(_ string, st Status)  { p.add(st.State) }
func (p *pubLog) add(s string)                    { p.mu.Lock(); p.states = append(p.states, s); p.mu.Unlock() }
func (p *pubLog) last() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.states[len(p.states)-1]
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func newTestService(t *testing.T) (*Service, *fakeSessions, *pubLog, *clock.Fake) {
	t.Helper()
	f := &fakeSessions{creates: make(chan terminal.Trigger, 8), answers: make(chan error, 8)}
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	n := 0
	s := New(Params{
		Manager: f, Clock: clk,
		ResolveEndpoint: func(_ context.Context, id, acc string) (*terminal.EndpointRef, error) {
			return &terminal.EndpointRef{ID: id, AccountID: acc}, nil
		},
		NewID: func() string { n++; return "t" + string(rune('0'+n)) },
	})
	pub := &pubLog{}
	s.SetPublisher(pub)
	t.Cleanup(s.Close)
	return s, f, pub, clk
}

func redeemAttached(t *testing.T, s *Service) string {
	t.Helper()
	m, err := s.Mint(context.Background(), MintParams{AccountID: "acc", EndpointID: "ep"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Redeem(context.Background(), RedeemParams{Token: m.Token, Reason: "why"})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := s.GuestByCookie(res.Cookie)
	if err := s.Attach(id); err != nil {
		t.Fatal(err)
	}
	return id
}

// Events from an attempt that is no longer current change nothing; a stale
// attempt that goes live anyway is closed, never admitted.
func TestStaleAttemptEventsAreIgnored(t *testing.T) {
	s, f, pub, _ := newTestService(t)
	gid := redeemAttached(t, s)
	first := <-f.creates
	f.answers <- errors.New("skipped")
	waitUntil(t, "refused", func() bool { return pub.last() == StateRefused })

	s.Retry(gid)
	second := <-f.creates
	if second.SessionID == first.SessionID {
		t.Fatal("retry reused the session id")
	}
	// Late events of the first attempt: an open (it must not admit, and is
	// closed), then its closed.
	f.emit(first.SessionID, terminal.StatusOpen, terminal.StatusOpening, "")
	if pub.last() != StatePending {
		t.Errorf("late open of an old attempt admitted the guest (%s)", pub.last())
	}
	f.emit(first.SessionID, terminal.StatusClosed, terminal.StatusOpen, terminal.CloseTicketNotAdmitted)
	if pub.last() != StatePending {
		t.Errorf("late closed of an old attempt changed the state to %s", pub.last())
	}
	waitUntil(t, "stale session closed", func() bool {
		for _, id := range f.closedIDs() {
			if id == first.SessionID {
				return true
			}
		}
		return false
	})
	// The current attempt still admits.
	f.answers <- nil
	waitUntil(t, "open", func() bool { return pub.last() == StateOpen })
	// An admitted session ending on the Manager side closes the guest.
	f.emit(second.SessionID, terminal.StatusClosed, terminal.StatusOpen, terminal.CloseIdleTimeout)
	if pub.last() != StateClosed {
		t.Errorf("state after the admitted session ended: %s", pub.last())
	}
	if _, ok := s.GuestAttached(second.SessionID); ok {
		t.Error("guest still tracked after close")
	}
}

// A capacity reservation is held from redemption and released by the close
// path; refused guest sessions count.
func TestCapacityCountsEveryLiveState(t *testing.T) {
	s, f, _, clk := newTestService(t)
	redeemAttached(t, s) // pending
	<-f.creates
	gid := redeemAttached(t, s)
	<-f.creates
	f.answers <- errors.New("skipped") // one of them refused
	m, _ := s.Mint(context.Background(), MintParams{AccountID: "acc", EndpointID: "ep"})
	if _, err := s.Redeem(context.Background(), RedeemParams{Token: m.Token, Reason: "x"}); err != nil {
		t.Fatalf("third: %v", err) // redeemed, never attached: counts too
	}
	extra, _ := s.Mint(context.Background(), MintParams{AccountID: "acc", EndpointID: "ep"})
	_, err := s.Redeem(context.Background(), RedeemParams{Token: extra.Token, Reason: "x"})
	var capErr *CapacityError
	if !errors.As(err, &capErr) || capErr.RetryAfter <= 0 {
		t.Fatalf("fourth: %v", err)
	}
	// The unattached one drops after the attach window, freeing a slot.
	clk.Advance(AttachWindow)
	s.Sweep()
	if _, err := s.Redeem(context.Background(), RedeemParams{Token: extra.Token, Reason: "x"}); err != nil {
		t.Errorf("after a slot freed: %v", err)
	}
	_ = gid
}

func TestValidateOptionsDefaults(t *testing.T) {
	o, err := ValidateOptions(Options{Label: " a\nb "})
	if err != nil || o.RedeemTTL != DefaultRedeemTTL || o.Lifetime != DefaultLifetime || o.Label != "ab" {
		t.Errorf("%+v %v", o, err)
	}
	for _, o := range []Options{{RedeemTTL: 59 * time.Second}, {Lifetime: 9 * time.Hour}} {
		if _, err := ValidateOptions(o); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
	for i := 0; i < 200; i++ {
		c := confirmationCode()
		for _, r := range c {
			if r == '0' || r == 'O' || r == '1' || r == 'I' {
				t.Fatalf("look-alike in %q", c)
			}
		}
	}
}
