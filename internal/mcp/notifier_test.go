// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package mcp

import (
	"sync"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/terminal"
)

// fakeSource stands in for terminal.Manager's subscription surface.
type fakeSource struct {
	out      func(string, int64)
	status   func(terminal.StatusEvent)
	sessions map[string]*terminal.Session
	unsubs   int
}

func (f *fakeSource) SubscribeOutput(fn func(string, int64)) func() {
	f.out = fn
	return func() { f.unsubs++ }
}
func (f *fakeSource) SubscribeStatus(fn func(terminal.StatusEvent)) func() {
	f.status = fn
	return func() { f.unsubs++ }
}
func (f *fakeSource) GetSession(id string) *terminal.Session { return f.sessions[id] }

type sent struct {
	method string
	params any
}

type recorder struct {
	mu   sync.Mutex
	msgs []sent
}

func (r *recorder) send(method string, params any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, sent{method, params})
}

func (r *recorder) snapshot() []sent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]sent(nil), r.msgs...)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

// A burst of output on an owned session collapses into ONE output_available
// carrying the newest offset; a foreign session produces nothing.
func TestNotifierDebouncesOutputPerOwnedSession(t *testing.T) {
	src := &fakeSource{sessions: map[string]*terminal.Session{}}
	rec := &recorder{}
	owned := map[string]bool{"sess_mine": true}
	n := attachNotifier(src, func(id string) bool { return owned[id] }, 20*time.Millisecond, rec.send)
	defer n.destroy()

	src.out("sess_mine", 10)
	src.out("sess_mine", 25)
	src.out("sess_other", 99)
	src.out("sess_mine", 42)

	waitFor(t, func() bool { return len(rec.snapshot()) == 1 })
	time.Sleep(50 * time.Millisecond) // nothing else may trail in
	got := rec.snapshot()
	if len(got) != 1 || got[0].method != notificationOutputAvailable {
		t.Fatalf("got %+v", got)
	}
	if p := got[0].params.(outputAvailableParams); p.SessionID != "sess_mine" || p.Offset != 42 {
		t.Errorf("params: %+v", p)
	}

	// A later burst notifies again.
	src.out("sess_mine", 50)
	waitFor(t, func() bool { return len(rec.snapshot()) == 2 })
}

// Status changes go out immediately with the endpoint id while the session is
// still known, and without it once it is gone.
func TestNotifierSessionStatus(t *testing.T) {
	src := &fakeSource{sessions: map[string]*terminal.Session{
		"sess_mine": {SessionID: "sess_mine", EndpointID: "ep-1"},
	}}
	rec := &recorder{}
	n := attachNotifier(src, func(id string) bool { return id == "sess_mine" }, 0, rec.send)
	defer n.destroy()

	src.status(terminal.StatusEvent{SessionID: "sess_mine", Status: terminal.StatusOpen})
	src.status(terminal.StatusEvent{SessionID: "sess_other", Status: terminal.StatusOpen})
	delete(src.sessions, "sess_mine")
	src.status(terminal.StatusEvent{SessionID: "sess_mine", Status: terminal.StatusClosed})

	got := rec.snapshot()
	if len(got) != 2 {
		t.Fatalf("want 2 status notifications, got %+v", got)
	}
	first := got[0].params.(sessionStatusParams)
	if first.Status != "open" || first.EndpointID != "ep-1" || got[0].method != notificationSessionStatus {
		t.Errorf("first: %+v", got[0])
	}
	if second := got[1].params.(sessionStatusParams); second.Status != "closed" || second.EndpointID != "" {
		t.Errorf("second: %+v", second)
	}
}

// destroy unsubscribes and cancels a pending debounce.
func TestNotifierDestroyDropsPending(t *testing.T) {
	src := &fakeSource{sessions: map[string]*terminal.Session{}}
	rec := &recorder{}
	n := attachNotifier(src, func(string) bool { return true }, 30*time.Millisecond, rec.send)
	src.out("sess_x", 1)
	n.destroy()
	time.Sleep(60 * time.Millisecond)
	if got := rec.snapshot(); len(got) != 0 {
		t.Errorf("pending notification fired after destroy: %+v", got)
	}
	if src.unsubs != 2 {
		t.Errorf("unsubscribed %d of 2", src.unsubs)
	}
}
