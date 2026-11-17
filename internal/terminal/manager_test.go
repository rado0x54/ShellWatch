// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package terminal

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
)

func mockManager(t *testing.T) (*Manager, *MockTransport) {
	t.Helper()
	mock := NewMockTransport()
	// t.Cleanup, not inline closes: a mid-test t.Fatal must not leak the pump
	// goroutine (closing the transport makes the pump exit).
	t.Cleanup(func() { _ = mock.Close() })
	factory := func(_ context.Context, _ FactoryParams) (Transport, error) { return mock, nil }
	return NewManager(factory, clock.Real{}, 0), mock
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func TestManagerCreateWriteReadClose(t *testing.T) {
	m, mock := mockManager(t)
	ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}

	sess, err := m.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI, SourceIP: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != StatusOpen || sess.Source != SourceUI || sess.SourceIP != "1.2.3.4" {
		t.Fatalf("session: %+v", sess)
	}

	// Input is echoed by the mock -> appears in output.
	if err := m.SendKeys(sess.SessionID, []string{"text:ls", "enter"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		r, _ := m.ReadOutput(sess.SessionID, 0, 100)
		return string(r.Data) == "ls\r"
	})
	if got := len(mock.Writes); got != 1 {
		t.Errorf("expected 1 write, got %d", got)
	}

	// Cross-account create is refused (#130).
	if _, err := m.Create(context.Background(), ep, "other", Trigger{Kind: SourceUI}); err == nil {
		t.Error("cross-account create must fail")
	}

	m.Close(sess.SessionID, CloseClientUI)
	waitFor(t, func() bool { return m.GetSession(sess.SessionID) == nil })
}

func TestManagerStatusHookOrdering(t *testing.T) {
	m, _ := mockManager(t)
	var events []Status
	m.SubscribeStatus(func(e StatusEvent) { events = append(events, e.Status) })

	ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	sess, _ := m.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
	m.Close(sess.SessionID, CloseClientUI)
	waitFor(t, func() bool { return m.GetSession(sess.SessionID) == nil })

	// opening->open (on create), then open->closing, closing->closed on close.
	if len(events) < 2 || events[0] != StatusOpen {
		t.Fatalf("status events: %v", events)
	}
	last := events[len(events)-1]
	if last != StatusClosed {
		t.Fatalf("final status should be closed, got %v (all: %v)", last, events)
	}
}

func TestManagerSessionLimitHelper(t *testing.T) {
	m, _ := mockManager(t)
	ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	m.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
	if !m.HasActiveSession("acc", "e1") || m.HasActiveSession("acc", "e2") || m.HasActiveSession("other", "e1") {
		t.Fatal("HasActiveSession scoping")
	}
	if len(m.ListForAccount("other")) != 0 {
		t.Error("account scoping leaked")
	}
}

// M6 (Node parity): a transport-driven close retains the session — buffer
// readable, hidden from lists — while an explicit Close removes it; errored
// sessions stay visible in lists.
func TestTerminalStateRetention(t *testing.T) {
	mgr, mock := mockManager(t)
	ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	sess, err := mgr.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.SendInput(sess.SessionID, "hello"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { r, _ := mgr.ReadOutput(sess.SessionID, 0, 100); return len(r.Data) > 0 })

	// Server hangup: transport dies underneath the manager.
	_ = mock.Close()
	waitFor(t, func() bool {
		s := mgr.GetSession(sess.SessionID)
		return s != nil && s.Status == StatusClosed
	})

	// Retained: post-mortem output stays readable, but lists hide it.
	if r, err := mgr.ReadOutput(sess.SessionID, 0, 100); err != nil || string(r.Data) != "hello" {
		t.Fatalf("post-mortem read: %q err=%v", r.Data, err)
	}
	if got := mgr.ListSessions(); len(got) != 0 {
		t.Fatalf("closed session listed: %+v", got)
	}
	if got := mgr.ListForAccount("acc"); len(got) != 0 {
		t.Fatalf("closed session in account list: %+v", got)
	}
	// Explicit Close on an already-closed session is a no-op: the retained
	// record survives until the retention limits remove it (removing it here
	// could clear the buffer while its closed broadcast is still draining).
	mgr.Close(sess.SessionID, CloseClientUI)
	if mgr.GetSession(sess.SessionID) == nil {
		t.Fatal("retained session dropped by a no-op Close")
	}

	// Errored sessions stay VISIBLE in lists (status filter is closed-only).
	mock2 := NewMockTransport()
	t.Cleanup(func() { _ = mock2.Close() })
	mgr2 := NewManager(func(context.Context, FactoryParams) (Transport, error) { return mock2, nil }, clock.Real{}, 0)
	sess2, err := mgr2.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	mock2.events <- Event{Err: context.DeadlineExceeded}
	waitFor(t, func() bool {
		s := mgr2.GetSession(sess2.SessionID)
		return s != nil && s.Status == StatusError
	})
	got := mgr2.ListSessions()
	if len(got) != 1 || got[0].Status != StatusError {
		t.Fatalf("errored session not listed: %+v", got)
	}
}

// An explicit Close removes the session entirely (registry + buffer).
func TestExplicitCloseRemovesSession(t *testing.T) {
	mgr, _ := mockManager(t)
	ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	sess, err := mgr.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	mgr.Close(sess.SessionID, CloseClientUI)
	if mgr.GetSession(sess.SessionID) != nil {
		t.Fatal("explicitly closed session still in registry")
	}
}

// Account deletion must purge retained post-mortem sessions (their buffers
// hold the deleted account's terminal output).
func TestRemoveForAccountPurgesRetainedSessions(t *testing.T) {
	mgr, mock := mockManager(t)
	ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	sess, err := mgr.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	_ = mock.Close() // server hangup -> retained post-mortem
	waitFor(t, func() bool {
		s := mgr.GetSession(sess.SessionID)
		return s != nil && s.Status == StatusClosed
	})
	if n := mgr.CloseAllForAccount("acc", CloseAccountDeleted); n != 0 {
		t.Fatalf("CloseAllForAccount touched retained session: %d", n)
	}
	if n := mgr.RemoveForAccount("acc"); n != 1 {
		t.Fatalf("RemoveForAccount: got %d, want 1", n)
	}
	if mgr.GetSession(sess.SessionID) != nil {
		t.Fatal("retained session survived account purge")
	}
}

// Regression: the pump used to start before the Open transition, so a
// transport dying immediately could finalize the session closed and then be
// flipped back to "open" by Create — a zombie session with no pump behind it
// (and an audit trail recording close-then-open). Open now happens before the
// pump starts, and terminal states are absorbing in setStatus.
func TestImmediateTransportDeathNeverReopens(t *testing.T) {
	mock := NewMockTransport()
	m := NewManager(func(context.Context, FactoryParams) (Transport, error) {
		_ = mock.Close() // dead before Create finishes its bookkeeping
		return mock, nil
	}, clock.Real{}, 0)
	ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}

	sess, err := m.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		s := m.GetSession(sess.SessionID)
		return s != nil && s.Status == StatusClosed
	})

	// Terminal states are absorbing: no late transition resurrects the session.
	mg, err := m.get(sess.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	m.setStatus(mg, StatusOpen, "")
	if s := m.GetSession(sess.SessionID); s.Status != StatusClosed {
		t.Fatalf("terminal state overwritten back to %s", s.Status)
	}
}

// Regression: Create's returned snapshot must be copied under the lock — the
// open broadcast fires synchronously inside Create, and a subscriber can hand
// the session id to another goroutine that closes it (mutating Status and
// CloseReason) while the unlocked copy is still in flight. Run under -race.
func TestCreateSnapshotDoesNotRaceImmediateClose(t *testing.T) {
	for i := 0; i < 20; i++ {
		mock := NewMockTransport()
		t.Cleanup(func() { _ = mock.Close() }) // pump exits even on a mid-round t.Fatal
		m := NewManager(func(context.Context, FactoryParams) (Transport, error) { return mock, nil }, clock.Real{}, 0)

		closed := make(chan struct{})
		unsub := m.SubscribeStatus(func(e StatusEvent) {
			if e.Status == StatusOpen {
				go func() { // a client reacting to the sessions:changed broadcast
					m.Close(e.SessionID, CloseClientWS)
					close(closed)
				}()
			}
		})

		ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
		sess, err := m.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
		if err != nil {
			t.Fatal(err)
		}
		if sess.SessionID == "" {
			t.Fatal("empty snapshot")
		}
		<-closed
		unsub()
	}
}

// Close joins the pump before the Closed broadcast: every data event the
// transport already delivered is appended (and announced) first, so a status
// subscriber reading the buffer at Closed always sees the complete output —
// the WS tail-drain contract depends on it. Before the join, Close could
// broadcast while the pump still had queued events, which Clear then destroyed.
func TestCloseJoinsPumpBeforeClosedBroadcast(t *testing.T) {
	const rounds = 20
	for i := 0; i < rounds; i++ {
		mgr, mock := mockManager(t)
		ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
		sess, err := mgr.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
		if err != nil {
			t.Fatal(err)
		}
		var atClosed int
		unsub := mgr.SubscribeStatus(func(e StatusEvent) {
			if e.SessionID == sess.SessionID && e.Status == StatusClosed {
				r, _ := mgr.ReadOutput(sess.SessionID, 0, 1<<20)
				atClosed = len(r.Data)
			}
		})
		total := 0
		for j := 0; j < 40; j++ { // queue events faster than the pump drains
			mock.Push([]byte("0123456789"))
			total += 10
		}
		mgr.Close(sess.SessionID, CloseClientUI)
		unsub()
		if atClosed != total {
			t.Fatalf("round %d: Closed broadcast saw %d/%d buffered bytes", i, atClosed, total)
		}
	}
}

// Destroy marks the manager destroyed under the same lock the id snapshot is
// taken under: a Create landing afterwards (an in-flight request racing
// shutdown) is refused before it ever dials — no session can be created, and
// no transport opened, after Destroy.
func TestCreateAfterDestroyRefused(t *testing.T) {
	dialed := false
	mgr := NewManager(func(context.Context, FactoryParams) (Transport, error) {
		dialed = true
		return NewMockTransport(), nil
	}, clock.Real{}, 0)
	mgr.Destroy()
	ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	if _, err := mgr.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI}); err == nil {
		t.Fatal("Create after Destroy must refuse")
	}
	if dialed {
		t.Fatal("refused Create still dialed a transport")
	}
	if n := len(mgr.ListSessions()); n != 0 {
		t.Fatalf("session registered after Destroy: %d", n)
	}
}

// Closing absorbs Open: Destroy (or an account deletion) can hit a session
// between Create registering it and Create's setStatus(Open) — the session
// must not broadcast closing -> open -> closed (a dead session resurrecting).
func TestClosingAbsorbsOpen(t *testing.T) {
	mgr, _ := mockManager(t)
	ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	sess, err := mgr.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	mg, err := mgr.get(sess.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	var sawOpenAfterClosing bool
	unsub := mgr.SubscribeStatus(func(e StatusEvent) {
		if e.Status == StatusOpen && e.Previous == StatusClosing {
			sawOpenAfterClosing = true
		}
	})
	defer unsub()
	if !mgr.beginClosing(mg, CloseShutdown) {
		t.Fatal("beginClosing refused an open session")
	}
	mgr.setStatus(mg, StatusOpen, "") // Create's late Open transition
	if s := mgr.GetSession(sess.SessionID); s.Status != StatusClosing {
		t.Fatalf("closing session resurrected to %s", s.Status)
	}
	if sawOpenAfterClosing {
		t.Fatal("subscribers watched a closing session broadcast open")
	}
}

// wedgedTransport breaks the Transport contract: Close never terminates
// Events. Manager.Close must still return within closeJoinTimeout, finalize
// Closed, and remove the session — liveness over completeness.
type wedgedTransport struct{ events chan Event }

func (w *wedgedTransport) Write([]byte) error    { return nil }
func (w *wedgedTransport) Resize(int, int) error { return nil }
func (w *wedgedTransport) Close() error          { return nil } // never closes events
func (w *wedgedTransport) Events() <-chan Event  { return w.events }

func TestCloseJoinIsBounded(t *testing.T) {
	wedged := &wedgedTransport{events: make(chan Event)}
	clk := clock.NewFake(time.Unix(1000, 0))
	m := NewManager(func(context.Context, FactoryParams) (Transport, error) { return wedged, nil }, clk, 0)
	m.closeJoinTimeout = 5 * time.Second
	ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	sess, err := m.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	mg, err := m.get(sess.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		m.Close(sess.SessionID, CloseClientUI)
		close(done)
	}()
	// Fire the fake-clock join timer (poll: Close's After registers from the
	// goroutine above; repeated advances are harmless).
	deadline := time.Now().Add(5 * time.Second)
	for {
		clk.Advance(m.closeJoinTimeout)
		select {
		case <-done:
		case <-time.After(5 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatal("Close wedged behind a transport that never terminates Events")
			}
			continue
		}
		break
	}
	if m.GetSession(sess.SessionID) != nil {
		t.Fatal("wedged session not removed")
	}

	// The abandoned pump must DISCARD late events, not refill the cleared
	// buffer of a session that is gone (possibly a deleted account's).
	off := mg.output.CurrentOffset()
	wedged.events <- Event{Data: []byte("late data for a dead session")}
	close(wedged.events) // pump drains the event, then exits
	<-mg.pumpDone
	if got := mg.output.CurrentOffset(); got != off {
		t.Fatalf("abandoned pump refilled the buffer: offset %d -> %d", off, got)
	}
}

// Destroy / sweeps close sessions concurrently: with N wedged transports the
// total stall is one closeJoinTimeout, not N of them.
func TestDestroyBoundsWedgedClosesConcurrently(t *testing.T) {
	const n = 5
	clk := clock.NewFake(time.Unix(1000, 0))
	transports := make([]*wedgedTransport, 0, n)
	m := NewManager(func(context.Context, FactoryParams) (Transport, error) {
		w := &wedgedTransport{events: make(chan Event)}
		transports = append(transports, w)
		return w, nil
	}, clk, 0)
	m.closeJoinTimeout = 5 * time.Second
	ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	sessions := make([]*Session, 0, n)
	for i := 0; i < n; i++ {
		sess, err := m.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, sess)
	}
	var mgs []*managed
	for _, sess := range sessions {
		mg, err := m.get(sess.SessionID)
		if err != nil {
			t.Fatal(err)
		}
		mgs = append(mgs, mg)
	}
	done := make(chan struct{})
	go func() {
		m.Destroy()
		close(done)
	}()
	// A single advance of one timeout must release ALL joins: serial closes
	// would register each waiter only after the previous one fired and need n
	// advances of a monotonically later deadline.
	deadline := time.Now().Add(10 * time.Second)
	for {
		clk.Advance(m.closeJoinTimeout)
		select {
		case <-done:
		case <-time.After(5 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatal("Destroy did not complete")
			}
			continue
		}
		break
	}
	if len(m.ListSessions()) != 0 {
		t.Fatal("sessions survived Destroy")
	}
	for _, w := range transports {
		close(w.events)
	}
	for _, mg := range mgs {
		<-mg.pumpDone
	}
}

// Removed hooks fire exactly once per session even when an explicit Close
// races RemoveForAccount: the delete under m.mu decides the winner.
func TestRemovedHookFiresOnceUnderCloseRemoveRace(t *testing.T) {
	mgr, _ := mockManager(t)
	var fires atomic.Int32
	unsubRemoved := mgr.SubscribeRemoved(func(string) { fires.Add(1) })
	defer unsubRemoved()
	// The pump broadcasts Closed while Close is parked on the join; purging
	// the account from inside that broadcast deletes the session before Close
	// resumes — the classic double-fire interleaving, now deterministic.
	unsubStatus := mgr.SubscribeStatus(func(e StatusEvent) {
		if e.Status == StatusClosed {
			mgr.RemoveForAccount("acc")
		}
	})
	defer unsubStatus()

	ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	sess, err := mgr.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	mgr.Close(sess.SessionID, CloseClientUI)
	if got := fires.Load(); got != 1 {
		t.Fatalf("removed hook fired %d times, want exactly 1", got)
	}
	if mgr.GetSession(sess.SessionID) != nil {
		t.Fatal("session survived")
	}
}

// The removed hook fires once per removal, on explicit close and on the
// account purge — it is what lets the WS hub sweep attaches that raced the
// registry delete.
func TestRemovedHookFires(t *testing.T) {
	mgr, _ := mockManager(t)
	var removed []string
	unsub := mgr.SubscribeRemoved(func(id string) { removed = append(removed, id) })
	defer unsub()

	ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	sess, err := mgr.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	mgr.Close(sess.SessionID, CloseClientUI)
	if len(removed) != 1 || removed[0] != sess.SessionID {
		t.Fatalf("explicit close: removed hook got %v", removed)
	}

	// Retained post-mortem session purged by account deletion.
	mock2 := NewMockTransport()
	t.Cleanup(func() { _ = mock2.Close() })
	mgr2 := NewManager(func(context.Context, FactoryParams) (Transport, error) { return mock2, nil }, clock.Real{}, 0)
	removed = nil
	unsub2 := mgr2.SubscribeRemoved(func(id string) { removed = append(removed, id) })
	defer unsub2()
	sess2, err := mgr2.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	_ = mock2.Close() // transport death -> retained post-mortem
	waitFor(t, func() bool {
		s := mgr2.GetSession(sess2.SessionID)
		return s != nil && s.Status == StatusClosed
	})
	if n := mgr2.RemoveForAccount("acc"); n != 1 {
		t.Fatalf("RemoveForAccount: %d", n)
	}
	if len(removed) != 1 || removed[0] != sess2.SessionID {
		t.Fatalf("account purge: removed hook got %v", removed)
	}
}

// The registered hook fires once per Create, after the session is in the
// registry (status opening) and before the factory runs (#273).
func TestRegisteredHookFiresBeforeFactory(t *testing.T) {
	mock := NewMockTransport()
	t.Cleanup(func() { _ = mock.Close() })
	var mgr *Manager
	var events []string
	mgr = NewManager(func(_ context.Context, p FactoryParams) (Transport, error) {
		events = append(events, "factory:"+p.SessionID)
		return mock, nil
	}, clock.Real{}, 0)
	unsub := mgr.SubscribeRegistered(func(sessionID, accountID string) {
		s := mgr.GetSession(sessionID)
		if s == nil || s.Status != StatusOpening {
			t.Errorf("hook saw session %+v, want registered and opening", s)
		}
		events = append(events, "registered:"+sessionID+":"+accountID)
	})

	ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	sess, err := mgr.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"registered:" + sess.SessionID + ":acc", "factory:" + sess.SessionID}
	if len(events) != 2 || events[0] != want[0] || events[1] != want[1] {
		t.Fatalf("events = %v, want %v", events, want)
	}

	unsub()
	mgr.Close(sess.SessionID, CloseClientUI)
	if _, err := mgr.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 { // factory only; the unsubscribed hook stays silent
		t.Fatalf("after unsubscribe: events = %v", events)
	}
}

// A size requested while the session is still connecting (a browser attached
// to an opening session) is applied once the transport is adopted, before the
// session opens; a later Resize still wins (#273 review).
func TestResizeWhileOpeningIsAppliedOnOpen(t *testing.T) {
	mock := NewMockTransport()
	t.Cleanup(func() { _ = mock.Close() })
	approve := make(chan struct{})
	mgr := NewManager(func(ctx context.Context, _ FactoryParams) (Transport, error) {
		select {
		case <-approve:
			return mock, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}, clock.Real{}, 0)

	registered := make(chan string, 1)
	unsub := mgr.SubscribeRegistered(func(id, _ string) { registered <- id })
	defer unsub()

	ep := EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	opened := make(chan *Session, 1)
	go func() {
		sess, err := mgr.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
		if err != nil {
			t.Error(err)
		}
		opened <- sess
	}()
	id := <-registered

	// Two layout passes while connecting: only the latest size matters.
	if err := mgr.Resize(id, 100, 30); err != nil {
		t.Fatalf("resize while opening: %v", err)
	}
	if err := mgr.Resize(id, 120, 40); err != nil {
		t.Fatalf("resize while opening: %v", err)
	}
	if got := mock.Sizes(); len(got) != 0 {
		t.Fatalf("no transport yet, but sizes = %v", got)
	}

	close(approve)
	sess := <-opened
	if sess == nil || sess.Status != StatusOpen {
		t.Fatalf("session = %+v, want open", sess)
	}
	if got := mock.Sizes(); len(got) != 1 || got[0] != [2]int{120, 40} {
		t.Fatalf("sizes after open = %v, want [[120 40]]", got)
	}

	if err := mgr.Resize(id, 90, 20); err != nil {
		t.Fatal(err)
	}
	if got := mock.Sizes(); len(got) != 2 || got[1] != [2]int{90, 20} {
		t.Fatalf("sizes after later resize = %v", got)
	}
}

// Only an opening session buffers a size; Resize on an unknown session still
// errors.
func TestResizeUnknownSessionErrors(t *testing.T) {
	mgr, _ := mockManager(t)
	if err := mgr.Resize("nope", 80, 24); err == nil {
		t.Error("resize of an unknown session must fail")
	}
}

// Ended sessions are retained for EndedRetention and at most
// MaxEndedPerAccount per account (oldest dropped first); they never count
// as active.
func TestEndedSessionRetentionBounds(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	var mu sync.Mutex
	var mocks []*MockTransport
	mgr := NewManager(func(context.Context, FactoryParams) (Transport, error) {
		tr := NewMockTransport()
		mu.Lock()
		mocks = append(mocks, tr)
		mu.Unlock()
		return tr, nil
	}, clk, 0)
	ep := EndpointRef{ID: "ep", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	hangUp := func() string {
		t.Helper()
		sess, err := mgr.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		tr := mocks[len(mocks)-1]
		mu.Unlock()
		_ = tr.Close()
		waitFor(t, func() bool {
			s := mgr.GetSession(sess.SessionID)
			return s == nil || s.Status == StatusClosed
		})
		return sess.SessionID
	}

	first := hangUp()
	if mgr.HasActiveSession("acc", "ep") {
		t.Error("an ended session counts as active")
	}
	clk.Advance(EndedRetention - time.Second)
	mgr.SweepEnded()
	if mgr.GetSession(first) == nil {
		t.Fatal("dropped before the retention elapsed")
	}
	clk.Advance(time.Second)
	mgr.SweepEnded()
	if mgr.GetSession(first) != nil {
		t.Fatal("kept past the retention")
	}

	// The count cap: the 11th ended session drops the oldest.
	var ids []string
	for i := 0; i < MaxEndedPerAccount+1; i++ {
		clk.Advance(time.Second)
		ids = append(ids, hangUp())
	}
	if mgr.GetSession(ids[0]) != nil {
		t.Error("oldest ended session kept beyond the cap")
	}
	for _, id := range ids[1:] {
		if mgr.GetSession(id) == nil {
			t.Errorf("ended session %s dropped within the cap", id)
		}
	}
}

// Only sessions that ended on their own are retained: explicitly closed ones
// are removed and never count toward MaxEndedPerAccount, so closing sessions
// does not evict retained ones.
func TestExplicitCloseDoesNotEvictRetained(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	var mu sync.Mutex
	var last *MockTransport
	mgr := NewManager(func(context.Context, FactoryParams) (Transport, error) {
		tr := NewMockTransport()
		mu.Lock()
		last = tr
		mu.Unlock()
		return tr, nil
	}, clk, 0)
	ep := EndpointRef{ID: "ep", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	var retained []string
	for i := 0; i < MaxEndedPerAccount; i++ {
		clk.Advance(time.Second)
		sess, err := mgr.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		tr := last
		mu.Unlock()
		_ = tr.Close()
		waitFor(t, func() bool {
			s := mgr.GetSession(sess.SessionID)
			return s != nil && s.Status == StatusClosed
		})
		retained = append(retained, sess.SessionID)
	}
	sess, err := mgr.Create(context.Background(), ep, "acc", Trigger{Kind: SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	mgr.Close(sess.SessionID, CloseClientUI)
	for _, id := range retained {
		if mgr.GetSession(id) == nil {
			t.Errorf("retained %s evicted by an explicit close", id)
		}
	}
}
