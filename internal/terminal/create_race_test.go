// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Close vs. in-flight Create: the factory can block for minutes (human
// approval of the SSH signature), and consent revocation / account deletion /
// shutdown must reach a session that is still connecting — either by
// cancelling the factory or by refusing the transport it still returns.
package terminal

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
)

func startBlockedCreate(t *testing.T, factory TransportFactory) (*Manager, string, chan error, chan string) {
	t.Helper()
	started := make(chan string, 1)
	done := make(chan error, 1)
	mgr := NewManager(func(ctx context.Context, p FactoryParams) (Transport, error) {
		started <- p.SessionID
		return factory(ctx, p)
	}, clock.Real{}, 0)
	go func() {
		_, err := mgr.Create(context.Background(),
			EndpointRef{ID: "ep", AccountID: "acc"}, "acc",
			Trigger{Kind: SourceMCP, OwnerClientID: "client-1", Reason: "race test"})
		done <- err
	}()
	select {
	case sid := <-started:
		return mgr, sid, done, started
	case <-time.After(3 * time.Second):
		t.Fatal("factory never started")
		return nil, "", nil, nil
	}
}

// Consent revocation during connection setup cancels the factory; the session
// never goes live and the manager forgets it.
func TestCloseAllForClientReachesInFlightCreate(t *testing.T) {
	var cancelled atomic.Bool
	mgr, sid, done, _ := startBlockedCreate(t, func(ctx context.Context, _ FactoryParams) (Transport, error) {
		<-ctx.Done()
		cancelled.Store(true)
		return nil, ctx.Err()
	})

	// The in-flight setup is registered and owned, so the sweep finds it.
	if n := mgr.CloseAllForClient("acc", "client-1", CloseAgentDisconnect); n != 1 {
		t.Fatalf("CloseAllForClient: closed %d, want 1 (in-flight create invisible to the sweep)", n)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("create succeeded after revocation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("create did not unwind after revocation")
	}
	if !cancelled.Load() {
		t.Error("factory context was not cancelled")
	}
	if s := mgr.GetSession(sid); s != nil {
		t.Fatalf("session survived revocation: %+v", s)
	}
}

// A factory that ignores cancellation and connects anyway: the transport must
// be closed on the spot and the session must not go live.
func TestCloseDuringCreateRefusesLateTransport(t *testing.T) {
	release := make(chan struct{})
	mock := NewMockTransport()
	mgr, sid, done, _ := startBlockedCreate(t, func(context.Context, FactoryParams) (Transport, error) {
		<-release // ignores ctx: the connection completes regardless
		return mock, nil
	})

	mgr.Close(sid, CloseAccountDeleted)
	close(release)

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "closed during connection setup") {
			t.Fatalf("create error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("create did not unwind")
	}
	if s := mgr.GetSession(sid); s != nil {
		t.Fatalf("session survived close-during-setup: %+v", s)
	}
	// The late transport was closed, not leaked: its event channel terminates.
	select {
	case ev, ok := <-mock.Events():
		if ok && !ev.Closed {
			t.Fatalf("unexpected transport event: %+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("late transport was never closed")
	}
}

// The happy path still works with pre-registration: a Create that finishes
// uninterrupted opens, pumps, and closes normally.
func TestCreateStillOpensAfterPreRegistration(t *testing.T) {
	mock := NewMockTransport()
	mgr := NewManager(func(context.Context, FactoryParams) (Transport, error) {
		return mock, nil
	}, clock.Real{}, 0)
	sess, err := mgr.Create(context.Background(),
		EndpointRef{ID: "ep", AccountID: "acc"}, "acc", Trigger{Kind: SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != StatusOpen {
		t.Fatalf("status: %s", sess.Status)
	}
	if err := mgr.SendInput(sess.SessionID, "hi"); err != nil {
		t.Fatal(err)
	}
	mgr.Close(sess.SessionID, CloseClientUI)
	if s := mgr.GetSession(sess.SessionID); s != nil {
		t.Fatalf("closed session still registered: %+v", s)
	}
}
