// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Regression tests for the slow-client overflow path: dropping a slow client
// must close the outbound channel (exactly once), so the writer goroutine and
// Serve's close/<-writerDone teardown always finish — before the fix the dead
// conn could leak in the hub with its writer blocked on an empty channel.
package ws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
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
