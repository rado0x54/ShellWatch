// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package terminal

import (
	"context"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
)

func mockManager(t *testing.T) (*Manager, *MockTransport) {
	t.Helper()
	mock := NewMockTransport()
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
	if ids := m.EndpointIDsForAccount("acc"); len(ids) != 1 || ids[0] != "e1" {
		t.Fatalf("endpoint ids: %v", ids)
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
	// Explicit Close on an already-closed session is a no-op (Node close()
	// early-return): the post-mortem record survives.
	mgr.Close(sess.SessionID, CloseClientUI)
	if mgr.GetSession(sess.SessionID) == nil {
		t.Fatal("post-mortem session dropped by no-op Close")
	}

	// Errored sessions stay VISIBLE in lists (status filter is closed-only).
	mock2 := NewMockTransport()
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
