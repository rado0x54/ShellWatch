// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package ws

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/coder/websocket"

	"github.com/rado0x54/shellwatch/internal/terminal"
)

// conn is one browser connection: its account, per-session attached/controlled
// state, per-session last-sent output offset, and a bounded outbound queue
// drained by a single writer goroutine (spec §5.7: preserve per-connection
// ordering; drop a slow client rather than block the hub).
type conn struct {
	ws        *websocket.Conn
	accountID string

	mu         sync.Mutex
	attached   map[string]bool
	controlled map[string]bool
	lastOffset map[string]int64

	// flushMu orders every per-session frame — flush, attach catch-up,
	// detach, terminal:closed — by construction: any operation that reads a
	// session's offset state and enqueues frames for it holds flushMu for the
	// whole read+enqueue, so no interleaving can duplicate output, resend a
	// caught-up delta, or enqueue output after the closed frame.
	flushMu sync.Mutex

	out    chan []byte
	closed bool
}

func newConn(wsc *websocket.Conn, accountID string) *conn {
	return &conn{
		ws: wsc, accountID: accountID,
		attached: map[string]bool{}, controlled: map[string]bool{}, lastOffset: map[string]int64{},
		out: make(chan []byte, 256),
	}
}

// startWriter drains the outbound queue in order; returns a done channel.
func (c *conn) startWriter(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for raw := range c.out {
			if err := c.ws.Write(ctx, websocket.MessageText, raw); err != nil {
				return
			}
		}
	}()
	return done
}

// enqueueLocked queues raw with c.mu held. On overflow it marks the
// connection closed AND closes the outbound channel — the writer drains what
// is queued and exits, so Serve's close/<-writerDone teardown always finishes
// and the hub entry is removed. Returns false on overflow; the caller must
// drop the websocket after releasing the lock.
func (c *conn) enqueueLocked(raw []byte) bool {
	if c.closed {
		return true
	}
	select {
	case c.out <- raw:
		return true
	default:
		// Slow client: drop the connection rather than block the hub.
		c.closed = true
		close(c.out)
		return false
	}
}

func (c *conn) enqueue(raw []byte) {
	c.mu.Lock()
	ok := c.enqueueLocked(raw)
	c.mu.Unlock()
	if !ok {
		_ = c.ws.Close(websocket.StatusPolicyViolation, "send buffer overflow")
	}
}

func (c *conn) send(msg any) {
	raw, err := json.Marshal(msg)
	if err != nil {
		return
	}
	c.enqueue(raw)
}

func (c *conn) sendError(message string) {
	c.send(map[string]any{"type": "error", "message": message})
}

// close releases the writer (c.out is closed exactly once, here or on the
// overflow path) and shuts the socket; a second websocket close is a no-op.
func (c *conn) close() {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.out)
	}
	c.mu.Unlock()
	_ = c.ws.Close(websocket.StatusNormalClosure, "")
}

func (c *conn) isAttached(sessionID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.attached[sessionID]
}

func (c *conn) hasControl(sessionID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.controlled[sessionID]
}

// attachWithCatchUp marks the session attached, records the catch-up offset,
// and queues the initial frames in one critical section: a concurrent
// coalesced flush (hub onOutput) can only observe the attach after lastOffset
// is set and the catch-up frames are queued, so it can neither resend the
// caught-up data nor enqueue a later delta ahead of it. flushMu is held too:
// on a RE-attach the conn is already attached, so a flush already in flight
// could otherwise enqueue its stale delta after the catch-up reset frame and
// overwrite the fresh offset.
func (c *conn) attachWithCatchUp(sessionID string, control bool, offset int64, frames [][]byte) {
	c.flushMu.Lock()
	defer c.flushMu.Unlock()
	c.mu.Lock()
	c.attached[sessionID] = true
	if control {
		c.controlled[sessionID] = true
	}
	c.lastOffset[sessionID] = offset
	ok := true
	for _, raw := range frames {
		if ok = c.enqueueLocked(raw); !ok {
			break
		}
	}
	c.mu.Unlock()
	if !ok {
		_ = c.ws.Close(websocket.StatusPolicyViolation, "send buffer overflow")
	}
}

// detach holds flushMu so an in-flight flush can't resurrect the deleted
// lastOffset entry (or send to a session the client just left).
func (c *conn) detach(sessionID string) {
	c.flushMu.Lock()
	defer c.flushMu.Unlock()
	c.mu.Lock()
	delete(c.attached, sessionID)
	delete(c.controlled, sessionID)
	delete(c.lastOffset, sessionID)
	c.mu.Unlock()
}

// closeSession delivers terminal:closed and detaches in one flushMu critical
// section: a hub flush already in flight either finishes before the closed
// frame or observes the detach and sends nothing — output can never follow
// the closed frame. No-op when the session isn't attached.
func (c *conn) closeSession(sessionID string) {
	c.flushMu.Lock()
	defer c.flushMu.Unlock()
	c.mu.Lock()
	attached := c.attached[sessionID]
	delete(c.attached, sessionID)
	delete(c.controlled, sessionID)
	delete(c.lastOffset, sessionID)
	c.mu.Unlock()
	if attached {
		c.send(map[string]any{"type": "terminal:closed", "sessionId": sessionID})
	}
}

func (c *conn) takeControl(sessionID string) {
	c.mu.Lock()
	c.controlled[sessionID] = true
	c.mu.Unlock()
}

func (c *conn) releaseControl(sessionID string) {
	c.mu.Lock()
	delete(c.controlled, sessionID)
	c.mu.Unlock()
}

// flushOutput reads the buffer delta since this connection's last-sent offset
// and sends a terminal:output frame (the coalesced fan-out; W10), starting
// from the offset recorded at attach time. flushMu keeps concurrent flushes
// (attach vs onOutput) from reading the same offset and duplicating output.
func (c *conn) flushOutput(mgr *terminal.Manager, sessionID string) {
	c.flushMu.Lock()
	defer c.flushMu.Unlock()
	c.mu.Lock()
	attached := c.attached[sessionID]
	last := c.lastOffset[sessionID]
	c.mu.Unlock()
	// The caller's isAttached check raced a detach: don't send output (from a
	// zero offset, i.e. the whole buffer) to a session the client just left.
	if !attached {
		return
	}
	res, err := mgr.ReadOutputFrom(sessionID, &last)
	if err != nil {
		return
	}
	if len(res.Data) == 0 && !res.Reset {
		return
	}
	msg := map[string]any{
		"type": "terminal:output", "sessionId": sessionID,
		"data": string(res.Data), "offset": res.Offset,
	}
	if res.Reset {
		msg["reset"] = true
	}
	c.mu.Lock()
	c.lastOffset[sessionID] = res.Offset
	c.mu.Unlock()
	c.send(msg)
}
