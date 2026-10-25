// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Regression tests for the slow-client overflow path: dropping a slow client
// must close the outbound channel (exactly once), so the writer goroutine and
// Serve's close/<-writerDone teardown always finish — before the fix the dead
// conn could leak in the hub with its writer blocked on an empty channel.
package ws

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/rado0x54/shellwatch/internal/terminal"
)

// wsPair dials a real websocket against an httptest server and returns the
// server side (what newConn wraps) and the client side.
func wsPair(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()
	serverSide := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		serverSide <- c
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseNow() })
	s := <-serverSide
	t.Cleanup(func() { _ = s.CloseNow() })
	return s, client
}

func (c *conn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// The overflow drop must leave c.out CLOSED (with the queued frames still
// drainable): a writer that drains the buffer before the socket close
// surfaces as a write error then exits on the channel close instead of
// blocking on it forever.
func TestOverflowClosesOutboundChannel(t *testing.T) {
	s, _ := wsPair(t)
	c := newConn(s, "acc")

	msg := []byte(`{"n":1}`)
	for i := 0; i < cap(c.out)+1; i++ { // no writer draining: the last one overflows
		c.enqueue(msg)
	}
	if !c.isClosed() {
		t.Fatal("overflow did not mark the conn closed")
	}

	drained := 0
	timeout := time.After(2 * time.Second)
drain:
	for {
		select {
		case _, ok := <-c.out:
			if !ok {
				break drain
			}
			drained++
		case <-timeout:
			t.Fatal("outbound channel not closed after overflow — writer would block forever")
		}
	}
	if drained != cap(c.out) {
		t.Fatalf("drained %d queued frames, want %d", drained, cap(c.out))
	}

	c.close()      // Serve's teardown: must not double-close the channel
	c.enqueue(msg) // and later enqueues are no-ops
}

// End-to-end teardown: a client that never reads backs up the writer, the hub
// overflows and drops it, and Serve's close/<-writerDone must still complete.
func TestOverflowDropReleasesWriter(t *testing.T) {
	s, _ := wsPair(t) // client never reads: TCP backpressure blocks the writer
	c := newConn(s, "acc")
	writerDone := c.startWriter(context.Background())
	t.Cleanup(func() { c.close(); <-writerDone }) // close() is idempotent

	payload := []byte(strings.Repeat("x", 256*1024))
	for i := 0; i < 4*cap(c.out) && !c.isClosed(); i++ {
		c.enqueue(payload)
	}
	if !c.isClosed() {
		t.Fatal("overflow not provoked")
	}

	c.close()
	select {
	case <-writerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("writer goroutine leaked after overflow drop")
	}
}

// -race smoke test for the attach/detach/flush interleavings: coalesced
// flushes (pump side) running against re-attach and detach (read-loop side)
// must serialize on flushMu — a flush in flight across a re-attach used to
// enqueue its stale delta after the catch-up frames and rewind lastOffset,
// and a flush racing a detach could send a detached session the full buffer.
func TestFlushRacesAttachDetach(t *testing.T) {
	s, client := wsPair(t)
	go func() { // drain the client so the writer never overflows
		for {
			if _, _, err := client.Read(context.Background()); err != nil {
				return
			}
		}
	}()

	mock := terminal.NewMockTransport()
	mgr := terminal.NewManager(func(context.Context, terminal.FactoryParams) (terminal.Transport, error) {
		return mock, nil
	}, nil, 0)
	ep := terminal.EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	sess, err := mgr.Create(context.Background(), ep, "acc", terminal.Trigger{Kind: terminal.SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mgr.Close(sess.SessionID, terminal.CloseClientWS) })

	c := newConn(s, "acc")
	writerDone := c.startWriter(context.Background())
	t.Cleanup(func() { c.close(); <-writerDone })
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // the pump side: output + coalesced flushes
		defer wg.Done()
		for i := 0; i < 200; i++ {
			mock.Push([]byte("x"))
			if c.isAttached(sess.SessionID) {
				c.flushOutput(mgr, sess.SessionID)
			}
		}
	}()
	go func() { // the read-loop side: re-attach / detach / hub-close cycles
		defer wg.Done()
		for i := 0; i < 200; i++ {
			c.attachWithCatchUp(sess.SessionID, true, 0, [][]byte{[]byte(`{"type":"t"}`)})
			c.flushOutput(mgr, sess.SessionID)
			if i%2 == 0 {
				c.detach(sess.SessionID)
			} else {
				c.closeSession(mgr, sess.SessionID)
			}
		}
	}()
	wg.Wait()
}

// terminal:closed is ordered against output by flushMu: once the closed frame
// is enqueued, no in-flight flush may enqueue output for that session after
// it — the frame sequence a client observes never shows a session producing
// output past its close.
func TestNoOutputAfterClosedFrame(t *testing.T) {
	s, client := wsPair(t)
	type frame struct {
		Type      string `json:"type"`
		SessionID string `json:"sessionId"`
	}
	frames := make(chan frame, 16384)
	go func() {
		defer close(frames)
		for {
			_, raw, err := client.Read(context.Background())
			if err != nil {
				return
			}
			var f frame
			if json.Unmarshal(raw, &f) == nil {
				frames <- f
			}
		}
	}()

	mocks := make(chan *terminal.MockTransport, 1)
	mgr := terminal.NewManager(func(context.Context, terminal.FactoryParams) (terminal.Transport, error) {
		m := terminal.NewMockTransport()
		mocks <- m
		return m, nil
	}, nil, 0)
	c := newConn(s, "acc")
	writerDone := c.startWriter(context.Background())
	t.Cleanup(func() { c.close(); <-writerDone })

	ep := terminal.EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	for i := 0; i < 100; i++ {
		sess, err := mgr.Create(context.Background(), ep, "acc", terminal.Trigger{Kind: terminal.SourceUI})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { mgr.Close(sess.SessionID, terminal.CloseClientWS) })
		mock := <-mocks
		c.attachWithCatchUp(sess.SessionID, true, 0, nil)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { // the pump side keeps flushing while the hub closes
			defer wg.Done()
			for j := 0; j < 20; j++ {
				mock.Push([]byte("x"))
				c.flushOutput(mgr, sess.SessionID)
			}
		}()
		go func() {
			defer wg.Done()
			c.closeSession(mgr, sess.SessionID)
		}()
		wg.Wait()
	}
	c.close()
	<-writerDone

	closed := map[string]bool{}
	for f := range frames {
		switch f.Type {
		case "terminal:closed":
			closed[f.SessionID] = true
		case "terminal:output":
			if closed[f.SessionID] {
				t.Fatalf("terminal:output enqueued after terminal:closed for %s", f.SessionID)
			}
		}
	}
}

// wsFrame is the client-side decoding of the server frames the drain tests
// assert on.
type wsFrame struct {
	Type      string `json:"type"`
	SessionID string `json:"sessionId"`
	Data      string `json:"data"`
	Reset     bool   `json:"reset"`
}

// drainHarness wires a real ws pair, a mock-backed manager with one open
// attached session, a conn with a running writer, and a client-side frame
// drain. All teardown is registered via t.Cleanup, so a mid-test t.Fatal
// can't leak the pump or writer goroutines.
type drainHarness struct {
	c      *conn
	mgr    *terminal.Manager
	mock   *terminal.MockTransport
	sess   *terminal.Session
	frames chan wsFrame
}

func newDrainHarness(t *testing.T) *drainHarness {
	t.Helper()
	s, client := wsPair(t)
	frames := make(chan wsFrame, 256)
	go func() {
		defer close(frames)
		for {
			_, raw, err := client.Read(context.Background())
			if err != nil {
				return
			}
			var f wsFrame
			if json.Unmarshal(raw, &f) == nil {
				frames <- f
			}
		}
	}()

	mock := terminal.NewMockTransport()
	t.Cleanup(func() { _ = mock.Close() })
	mgr := terminal.NewManager(func(context.Context, terminal.FactoryParams) (terminal.Transport, error) {
		return mock, nil
	}, nil, 0)
	ep := terminal.EndpointRef{ID: "e1", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	sess, err := mgr.Create(context.Background(), ep, "acc", terminal.Trigger{Kind: terminal.SourceUI})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mgr.Close(sess.SessionID, terminal.CloseClientWS) })

	c := newConn(s, "acc")
	writerDone := c.startWriter(context.Background())
	t.Cleanup(func() { c.close(); <-writerDone })
	c.attachWithCatchUp(sess.SessionID, true, 0, nil)

	return &drainHarness{c: c, mgr: mgr, mock: mock, sess: sess, frames: frames}
}

// waitBuffered blocks until the pump has appended at least n bytes.
func (h *drainHarness) waitBuffered(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if r, err := h.mgr.ReadOutput(h.sess.SessionID, 0, 1<<20); err == nil && len(r.Data) >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("pump never delivered the output")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// expectTailThenClosed consumes frames until terminal:closed, asserting the
// tail arrived first and that no reset frame was emitted.
func (h *drainHarness) expectTailThenClosed(t *testing.T, tail string) {
	t.Helper()
	var sawTail bool
	timeout := time.After(5 * time.Second)
	for {
		select {
		case f, ok := <-h.frames:
			if !ok {
				t.Fatal("websocket closed before terminal:closed arrived")
			}
			if f.Type == "terminal:output" && f.Reset {
				t.Fatalf("close emitted a reset frame (blank terminal): %+v", f)
			}
			switch f.Type {
			case "terminal:output":
				if strings.Contains(f.Data, tail) {
					sawTail = true
				}
			case "terminal:closed":
				if !sawTail {
					t.Fatalf("output tail %q dropped on close — never reached the client", tail)
				}
				return
			}
		case <-timeout:
			t.Fatal("timed out waiting for terminal:closed")
		}
	}
}

// closeSession must deliver the output tail: when the close event beats the
// debounced output notification, the un-flushed final bytes (the shell's
// logout/exit output) are drained inside the same flushMu section, before the
// closed frame — not dropped by a late flush seeing a detached session. No
// hub is wired here, so the drain is the only path that can deliver the tail.
func TestCloseSessionDrainsOutputTail(t *testing.T) {
	h := newDrainHarness(t)
	h.mock.Push([]byte("logout\r\n"))
	h.waitBuffered(t, len("logout\r\n")) // buffered but never flushed
	h.c.closeSession(h.mgr, h.sess.SessionID)
	h.expectTailThenClosed(t, "logout")
}

// Regression (review round 5): Manager.Close used to clear the buffer BEFORE
// broadcasting Closed, so the hub's synchronous drain observed the offset
// rewinding and emitted terminal:output{reset:true,data:""} — blanking the
// client's scrollback on every explicit close. Close now joins the pump and
// broadcasts before clearing: an explicit close delivers the undelivered
// tail, then the closed frame, and never a reset.
func TestExplicitCloseDrainsTailWithoutReset(t *testing.T) {
	h := newDrainHarness(t)
	hub := NewHub(h.mgr)
	t.Cleanup(hub.Close)
	hub.add(h.c)
	t.Cleanup(func() { hub.remove(h.c) })

	h.mock.Push([]byte("before "))
	h.waitBuffered(t, len("before "))
	h.c.flushOutput(h.mgr, h.sess.SessionID) // client is caught up
	h.mock.Push([]byte("logout"))
	h.waitBuffered(t, len("before logout")) // tail buffered

	// Explicit close: the hub's status subscriber drains synchronously inside.
	h.mgr.Close(h.sess.SessionID, terminal.CloseClientUI)
	h.expectTailThenClosed(t, "logout")
}
