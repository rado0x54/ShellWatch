// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package ticket

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/audit"
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
	// hold, when set, delays Create's return after a successful open.
	hold   chan struct{}
	closed []closeReq
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
		if f.hold != nil {
			<-f.hold
		}
		return &terminal.Session{SessionID: tr.SessionID}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// open stands in for endpointsvc.Service.Open.
func (f *fakeSessions) open(ctx context.Context, acc, id string, tr terminal.Trigger) (*terminal.Session, error) {
	return f.Create(ctx, terminal.EndpointRef{ID: id, AccountID: acc}, acc, tr)
}

func (f *fakeSessions) Close(sessionID string, reason terminal.CloseReason) {
	f.mu.Lock()
	f.closed = append(f.closed, closeReq{sessionID: sessionID, reason: reason})
	f.mu.Unlock()
}

func (f *fakeSessions) SubscribeStatus(fn func(terminal.StatusEvent)) func() {
	f.sub = fn
	return func() {}
}

func (f *fakeSessions) emit(sid string, st, prev terminal.Status, reason terminal.CloseReason) {
	f.sub(terminal.StatusEvent{SessionID: sid, Status: st, Previous: prev, Reason: reason})
}

// closes returns the reasons sessionID was closed with, in order.
func (f *fakeSessions) closes(sessionID string) []terminal.CloseReason {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []terminal.CloseReason
	for _, c := range f.closed {
		if c.sessionID == sessionID {
			out = append(out, c.reason)
		}
	}
	return out
}

type pubLog struct {
	mu     sync.Mutex
	states []string
	closed Status
}

func (p *pubLog) GuestStatus(_ string, st Status) { p.add(st.State) }
func (p *pubLog) GuestOpen(string, string)        {}
func (p *pubLog) GuestClose(_ string, st Status) {
	p.mu.Lock()
	p.closed = st
	p.mu.Unlock()
	p.add(st.State)
}
func (p *pubLog) add(s string) { p.mu.Lock(); p.states = append(p.states, s); p.mu.Unlock() }
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
		Manager: f, Open: f.open, Clock: clk,
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

// One connect per guest session: a denial (or failed connect) closes it with
// "Access was not granted." and starts nothing else; an admitted session
// ending on the Manager side closes it with "The session has ended."
func TestOneConnectPerGuestSession(t *testing.T) {
	t.Run("denied", func(t *testing.T) {
		s, f, pub, _ := newTestService(t)
		redeemAttached(t, s)
		<-f.creates
		f.answers <- errors.New("skipped")
		waitUntil(t, "closed", func() bool { return pub.last() == StateClosed })
		if pub.closed.Message != MsgNotGranted {
			t.Errorf("closed message %q, want %q", pub.closed.Message, MsgNotGranted)
		}
		if len(s.List("acc")) != 0 {
			t.Error("the ended ticket is still listed")
		}
		select {
		case tr := <-f.creates:
			t.Errorf("a second connect started: %+v", tr)
		case <-time.After(50 * time.Millisecond):
		}
	})
	t.Run("admitted, then ended by the Manager", func(t *testing.T) {
		s, f, pub, _ := newTestService(t)
		redeemAttached(t, s)
		tr := <-f.creates
		if tr.Lifetime != DefaultLifetime || tr.LifetimeReason != terminal.CloseTicketLifetime {
			t.Errorf("trigger lifetime %v / %q", tr.Lifetime, tr.LifetimeReason)
		}
		f.answers <- nil
		waitUntil(t, "open", func() bool { return pub.last() == StateOpen })
		f.emit(tr.SessionID, terminal.StatusClosed, terminal.StatusOpen, terminal.CloseTicketLifetime)
		if pub.last() != StateClosed || pub.closed.Message != MsgEnded {
			t.Errorf("after the session ended: %s %q", pub.last(), pub.closed.Message)
		}
		if _, ok := s.GuestAttached(tr.SessionID); ok {
			t.Error("guest still tracked after close")
		}
	})
}

// #322: a revoke right after admission — before Create has even returned —
// closes the terminal session once, with ticket-revoked.
func TestRevokeRightAfterAdmission(t *testing.T) {
	s, f, pub, _ := newTestService(t)
	f.hold = make(chan struct{})
	redeemAttached(t, s)
	tr := <-f.creates
	f.answers <- nil
	waitUntil(t, "open", func() bool { return pub.last() == StateOpen })
	if err := s.Revoke("acc", s.List("acc")[0].ID); err != nil {
		t.Fatal(err)
	}
	close(f.hold)
	waitUntil(t, "session closed", func() bool { return len(f.closes(tr.SessionID)) > 0 })
	time.Sleep(50 * time.Millisecond) // nothing else may close it
	if got := f.closes(tr.SessionID); len(got) != 1 || got[0] != terminal.CloseTicketRevoked {
		t.Errorf("closes %v, want [%s]", got, terminal.CloseTicketRevoked)
	}
}

// A target change drops only that endpoint's unredeemed tickets bound to
// another target; one minted for the new target survives.
func TestRevokeStaleForEndpoint(t *testing.T) {
	s, f, _, _ := newTestService(t)
	redeemAttached(t, s)
	<-f.creates
	m, _ := s.Mint(context.Background(), MintParams{AccountID: "acc", EndpointID: "ep"})
	other, _ := s.Mint(context.Background(), MintParams{AccountID: "acc", EndpointID: "ep2"})
	current := terminal.EndpointRef{}.Target() // the fake resolver's target
	s.RevokeStaleForEndpoint("acc", "ep", current)
	if len(s.List("acc")) != 3 {
		t.Fatalf("a ticket for the current target was revoked: %d listed", len(s.List("acc")))
	}
	s.RevokeStaleForEndpoint("acc", "ep", "u@new.example:22")
	if _, err := s.Redeem(context.Background(), RedeemParams{Token: m.Token, Reason: "x"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unredeemed ticket survived: %v", err)
	}
	if _, err := s.Redeem(context.Background(), RedeemParams{Token: other.Token, Reason: "x"}); err != nil {
		t.Errorf("other endpoint's ticket revoked: %v", err)
	}
	if n := len(s.List("acc")); n != 2 { // the redeemed guest session and the other ticket
		t.Errorf("listed %d tickets, want 2", n)
	}
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

// A failed endpoint lookup at redeem time (database error, cancelled
// request) is not "endpoint gone": the ticket stays redeemable.
func TestRedeemEndpointLookupErrorKeepsTicket(t *testing.T) {
	f := &fakeSessions{creates: make(chan terminal.Trigger, 8), answers: make(chan error, 8)}
	var fail bool
	s := New(Params{
		Manager: f, Open: f.open, Clock: clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		ResolveEndpoint: func(_ context.Context, id, acc string) (*terminal.EndpointRef, error) {
			if fail {
				return nil, context.Canceled
			}
			return &terminal.EndpointRef{ID: id, AccountID: acc}, nil
		},
		NewID: func() string { return "tk" },
	})
	t.Cleanup(s.Close)
	m, err := s.Mint(context.Background(), MintParams{AccountID: "acc", EndpointID: "ep"})
	if err != nil {
		t.Fatal(err)
	}
	fail = true
	if _, err := s.Redeem(context.Background(), RedeemParams{Token: m.Token, Reason: "x"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("lookup error: %v, want ErrUnavailable", err)
	}
	fail = false
	if _, err := s.Redeem(context.Background(), RedeemParams{Token: m.Token, Reason: "x"}); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

// A ticket whose guest session ended leaves the owner's list at once (the
// audit keeps it); revoking it then is a plain not-found.
func TestEndedTicketLeavesTheList(t *testing.T) {
	s, _, _, clk := newTestService(t)
	m, err := s.Mint(context.Background(), MintParams{AccountID: "acc", EndpointID: "ep"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Redeem(context.Background(), RedeemParams{Token: m.Token, Reason: "x"}); err != nil {
		t.Fatal(err)
	}
	clk.Advance(AttachWindow)
	s.Sweep()
	if v := s.List("acc"); len(v) != 0 {
		t.Fatalf("ended ticket listed: %+v", v)
	}
	if err := s.Revoke("acc", m.Ticket.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoke of an ended ticket: %v", err)
	}
}

// blockingClose is a Manager whose Close hangs (a wedged transport).
type blockingClose struct {
	*fakeSessions
	release chan struct{}
}

func (b *blockingClose) Close(string, terminal.CloseReason) { <-b.release }

// A terminal close that hangs must not hold up the caller (the janitor, a
// revoke): the audit and owner notification go out first and the close runs
// in the background.
func TestCloseDoesNotWaitForATerminalClose(t *testing.T) {
	f := &fakeSessions{creates: make(chan terminal.Trigger, 8), answers: make(chan error, 8)}
	b := &blockingClose{fakeSessions: f, release: make(chan struct{})}
	t.Cleanup(func() { close(b.release) })
	s := New(Params{
		Manager: b, Open: f.open, Clock: clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		ResolveEndpoint: func(_ context.Context, id, acc string) (*terminal.EndpointRef, error) {
			return &terminal.EndpointRef{ID: id, AccountID: acc}, nil
		},
		NewID: func() string { return "tk" },
	})
	s.SetPublisher(&pubLog{})
	t.Cleanup(s.Close)
	redeemAttached(t, s)
	<-f.creates
	f.answers <- nil // admitted: an open terminal session to close
	waitUntil(t, "admitted", func() bool {
		v := s.List("acc")
		return len(v) == 1 && v[0].State == StateOpen
	})
	done := make(chan error, 1)
	go func() { done <- s.Revoke("acc", s.List("acc")[0].ID) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revoke waited for the hung terminal close")
	}
}

type countNotifier struct {
	mu               sync.Mutex
	tickets, session int
}

func (c *countNotifier) TicketsChanged(string) {
	c.mu.Lock()
	c.tickets++
	c.mu.Unlock()
}

func (c *countNotifier) SessionsChanged(string) {
	c.mu.Lock()
	c.session++
	c.mu.Unlock()
}

func (c *countNotifier) counts() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tickets, c.session
}

// A guest connection that flaps (detach, reattach, again and again) sends the
// owner one batched notification, not one per flip; a second tab attaching
// sends none.
func TestGuestFlapsAreBatchedForTheOwner(t *testing.T) {
	f := &fakeSessions{creates: make(chan terminal.Trigger, 8), answers: make(chan error, 8)}
	n := &countNotifier{}
	s := New(Params{
		Manager: f, Open: f.open, Clock: clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)), Notifier: n,
		ResolveEndpoint: func(_ context.Context, id, acc string) (*terminal.EndpointRef, error) {
			return &terminal.EndpointRef{ID: id, AccountID: acc}, nil
		},
		NewID: func() string { return "tk" },
	})
	s.SetPublisher(&pubLog{})
	t.Cleanup(s.Close)
	gid := redeemAttached(t, s)
	<-f.creates
	time.Sleep(attachNotifyDelay + 200*time.Millisecond) // let anything earlier settle
	before, _ := n.counts()

	for i := 0; i < 5; i++ {
		s.Detach(gid)
		if err := s.Attach(gid); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Attach(gid); err != nil { // a second tab
		t.Fatal(err)
	}
	if got, _ := n.counts(); got != before {
		t.Errorf("notified %d times before the batch delay", got-before)
	}
	waitUntil(t, "batched notification", func() bool { got, _ := n.counts(); return got == before+1 })
	time.Sleep(attachNotifyDelay + 200*time.Millisecond)
	if got, _ := n.counts(); got != before+1 {
		t.Errorf("%d notifications for 5 flips and a second tab, want 1", got-before)
	}
}

// A deadline that has passed is enforced by the next event itself, not only
// by the janitor: an approval after the admission window and a reconnect
// after the grace both end the guest session.
func TestDeadlinesHoldBetweenSweeps(t *testing.T) {
	t.Run("approval after the admission window", func(t *testing.T) {
		s, f, pub, clk := newTestService(t)
		redeemAttached(t, s)
		tr := <-f.creates
		clk.Advance(AdmissionWindow) // no Sweep
		f.answers <- nil             // the owner approves too late; the session goes live
		waitUntil(t, "closed", func() bool { return pub.last() == StateClosed })
		waitUntil(t, "late session closed", func() bool {
			got := f.closes(tr.SessionID)
			return len(got) == 1 && got[0] == terminal.CloseTicketNotAdmitted
		})
	})
	t.Run("reconnect after the grace", func(t *testing.T) {
		s, f, pub, clk := newTestService(t)
		gid := redeemAttached(t, s)
		<-f.creates
		f.answers <- nil
		waitUntil(t, "open", func() bool { return pub.last() == StateOpen })
		s.Detach(gid)
		clk.Advance(ReconnectGrace) // no Sweep
		if err := s.Attach(gid); !errors.Is(err, ErrGone) {
			t.Fatalf("attach after the grace: %v", err)
		}
		if pub.last() != StateClosed {
			t.Errorf("state %s, want closed", pub.last())
		}
	})
}

// The eligibility lookups run without the lock and can be slow: a ticket
// that expires during them is not consumed, and the attach window counts
// from the moment of consumption.
func TestRedeemRechecksExpiryAtConsumption(t *testing.T) {
	f := &fakeSessions{creates: make(chan terminal.Trigger, 8), answers: make(chan error, 8)}
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	var lookupTakes time.Duration
	n := 0
	rec := &auditLog{}
	s := New(Params{
		Manager: f, Open: f.open, Clock: clk, Audit: rec,
		ResolveEndpoint: func(_ context.Context, id, acc string) (*terminal.EndpointRef, error) {
			clk.Advance(lookupTakes) // a slow database
			return &terminal.EndpointRef{ID: id, AccountID: acc}, nil
		},
		NewID: func() string { n++; return "t" + string(rune('0'+n)) },
	})
	s.SetPublisher(&pubLog{})
	t.Cleanup(s.Close)

	// Mint looks the endpoint up too: keep it quick there.
	m, err := s.Mint(context.Background(), MintParams{AccountID: "acc", EndpointID: "ep"})
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(DefaultRedeemTTL - time.Second)
	lookupTakes = 2 * time.Second // expires while the lookup runs
	if _, err := s.Redeem(context.Background(), RedeemParams{Token: m.Token, Reason: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("redeem of a ticket that expired during the lookup: %v", err)
	}
	if len(s.List("acc")) != 0 {
		t.Error("the expired ticket is still listed")
	}
	// The same audit row as any other expiry, reason included.
	if ev, ok := rec.last(audit.TicketExpired); !ok || ev.EndReason != "expired" || ev.TicketID != m.Ticket.ID {
		t.Errorf("expired audit row: %+v (found %v)", ev, ok)
	}

	lookupTakes = 0
	m2, err := s.Mint(context.Background(), MintParams{AccountID: "acc", EndpointID: "ep"})
	if err != nil {
		t.Fatal(err)
	}
	lookupTakes = 10 * time.Second
	res, err := s.Redeem(context.Background(), RedeemParams{Token: m2.Token, Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	gid, _ := s.GuestByCookie(res.Cookie)
	s.mu.Lock()
	got := s.guests[gid].attachDeadline
	s.mu.Unlock()
	if want := clk.Now().Add(AttachWindow); !got.Equal(want) {
		t.Errorf("attach deadline %s, want %s (counted from consumption)", got, want)
	}

	// The janitor's expiry writes the same row shape as the redeem path.
	lookupTakes = 0
	m3, err := s.Mint(context.Background(), MintParams{AccountID: "acc", EndpointID: "ep"})
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(DefaultRedeemTTL)
	s.Sweep()
	if ev, ok := rec.last(audit.TicketExpired); !ok || ev.EndReason != "expired" || ev.TicketID != m3.Ticket.ID {
		t.Errorf("swept expired audit row: %+v (found %v)", ev, ok)
	}
}

// auditLog records ticket audit events in memory.
type auditLog struct {
	mu     sync.Mutex
	events []audit.TicketEvent
}

func (a *auditLog) Record(ev audit.TicketEvent) {
	a.mu.Lock()
	a.events = append(a.events, ev)
	a.mu.Unlock()
}

func (a *auditLog) last(name string) (audit.TicketEvent, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.events) - 1; i >= 0; i-- {
		if a.events[i].Event == name {
			return a.events[i], true
		}
	}
	return audit.TicketEvent{}, false
}
