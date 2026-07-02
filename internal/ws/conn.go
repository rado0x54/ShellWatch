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

func (c *conn) enqueue(raw []byte) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	select {
	case c.out <- raw:
		c.mu.Unlock()
	default:
		// Slow client: drop the connection rather than block the hub.
		c.closed = true
		c.mu.Unlock()
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

func (c *conn) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	close(c.out)
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

func (c *conn) attach(sessionID string, control bool) {
	c.mu.Lock()
	c.attached[sessionID] = true
	if control {
		c.controlled[sessionID] = true
	}
	c.mu.Unlock()
}

func (c *conn) detach(sessionID string) {
	c.mu.Lock()
	delete(c.attached, sessionID)
	delete(c.controlled, sessionID)
	delete(c.lastOffset, sessionID)
	c.mu.Unlock()
}

func (c *conn) clearSession(sessionID string) { c.detach(sessionID) }

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
// and sends a terminal:output frame (the coalesced fan-out; W10). setLast
// starts from the offset recorded at attach time.
func (c *conn) flushOutput(mgr *terminal.Manager, sessionID string) {
	c.mu.Lock()
	last := c.lastOffset[sessionID]
	c.mu.Unlock()
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

// setInitialOffset records the offset sent in the attach reply so subsequent
// coalesced flushes start from the right place.
func (c *conn) setInitialOffset(sessionID string, offset int64) {
	c.mu.Lock()
	c.lastOffset[sessionID] = offset
	c.mu.Unlock()
}
