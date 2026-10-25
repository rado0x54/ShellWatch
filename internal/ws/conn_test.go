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

// closeSession must deliver the output tail: when the close event beats the
// debounced output notification, the un-flushed final bytes (the shell's
// logout/exit output) are drained inside the same flushMu section, before the
// closed frame — not dropped by a late flush seeing a detached session.
func TestCloseSessionDrainsOutputTail(t *testing.T) {
	s, client := wsPair(t)

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

	type frame struct {
		Type string `json:"type"`
		Data string `json:"data"`
	}
	frames := make(chan frame, 256)
	go func() { // drain concurrently so the close handshake completes
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

	c := newConn(s, "acc")
	writerDone := c.startWriter(context.Background())
	t.Cleanup(func() { c.close(); <-writerDone })

	c.attachWithCatchUp(sess.SessionID, true, 0, nil)
	mock.Push([]byte("logout\r\n"))
	// Wait for the pump to land the bytes in the buffer, but do NOT flush —
	// this is the "close beats the output notification" interleaving.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if r, err := mgr.ReadOutput(sess.SessionID, 0, 100); err == nil && len(r.Data) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pump never delivered the output")
		}
		time.Sleep(2 * time.Millisecond)
	}
	c.closeSession(mgr, sess.SessionID)

	// The connection stays open (only the session closed): the tail and the
	// closed frame must arrive on the live stream, tail first.
	var sawTail, closedSeen bool
	timeout := time.After(5 * time.Second)
	for !closedSeen {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatal("websocket closed before terminal:closed arrived")
			}
			switch f.Type {
			case "terminal:output":
				if strings.Contains(f.Data, "logout") {
					sawTail = true
				}
			case "terminal:closed":
				closedSeen = true
			}
		case <-timeout:
			t.Fatal("timed out waiting for terminal:closed")
		}
	}
	if !sawTail {
		t.Fatal("output tail dropped on close — the logout bytes never reached the client")
	}
}
