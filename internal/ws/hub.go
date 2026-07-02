// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package ws is the single browser-WebSocket hub (spec §5.7, W3 fix): one
// registry owns every socket with its per-connection attached/controlled
// state, replacing the Node backend's dual ws-handler + WebSocketChannel
// registries. Output fan-out is coalesced read-since-offset (W10 fix):
// the Manager notifies (sessionID, offset), and each attached connection
// reads the delta since its own last-sent offset. Terminal protocol ports
// ws-message-router.ts; account-scoped sends give the pending-action layer
// (Phase 4) a narrow SendToAccount seam.
package ws

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/coder/websocket"

	"github.com/rado0x54/shellwatch/internal/terminal"
)

// Hub owns all browser connections.
type Hub struct {
	mgr *terminal.Manager

	mu    sync.Mutex
	conns map[*conn]struct{}

	unsubStatus func()
	unsubOutput func()
}

// NewHub wires the hub to the terminal manager's guaranteed status hook and
// coalesced output notifier.
func NewHub(mgr *terminal.Manager) *Hub {
	h := &Hub{mgr: mgr, conns: map[*conn]struct{}{}}
	h.unsubStatus = mgr.SubscribeStatus(h.onStatusChange)
	h.unsubOutput = mgr.SubscribeOutput(h.onOutput)
	return h
}

// Close detaches the hub's manager subscriptions.
func (h *Hub) Close() {
	if h.unsubStatus != nil {
		h.unsubStatus()
	}
	if h.unsubOutput != nil {
		h.unsubOutput()
	}
}

// SendToAccount delivers a server message to every connection owned by an
// account (the narrow seam the approval layer uses in Phase 4).
func (h *Hub) SendToAccount(accountID string, msg any) {
	raw, err := json.Marshal(msg)
	if err != nil {
		return
	}
	h.mu.Lock()
	targets := make([]*conn, 0)
	for c := range h.conns {
		if c.accountID == accountID {
			targets = append(targets, c)
		}
	}
	h.mu.Unlock()
	for _, c := range targets {
		c.enqueue(raw)
	}
}

func (h *Hub) add(c *conn) {
	h.mu.Lock()
	h.conns[c] = struct{}{}
	h.mu.Unlock()
}

func (h *Hub) remove(c *conn) {
	h.mu.Lock()
	delete(h.conns, c)
	h.mu.Unlock()
}

// onStatusChange broadcasts an account-scoped sessions:changed to every
// connection, plus terminal:closed to connections attached to a now-closed
// session (the Node onClose behavior). Low-frequency, so not coalesced.
func (h *Hub) onStatusChange(ev terminal.StatusEvent) {
	terminalState := ev.Status == terminal.StatusClosed || ev.Status == terminal.StatusError
	h.mu.Lock()
	conns := make([]*conn, 0, len(h.conns))
	for c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.Unlock()
	for _, c := range conns {
		if terminalState && c.isAttached(ev.SessionID) {
			c.send(map[string]any{"type": "terminal:closed", "sessionId": ev.SessionID})
			c.clearSession(ev.SessionID)
		}
		c.send(h.sessionList(c))
	}
}

// onOutput delivers the coalesced delta to attached connections.
func (h *Hub) onOutput(sessionID string, _ int64) {
	h.mu.Lock()
	conns := make([]*conn, 0, len(h.conns))
	for c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.Unlock()
	for _, c := range conns {
		if c.isAttached(sessionID) {
			c.flushOutput(h.mgr, sessionID)
		}
	}
}

// sessionList builds an account-scoped sessions:changed for a connection
// (buildSessionList in ws-message-router.ts).
func (h *Hub) sessionList(c *conn) map[string]any {
	entries := make([]sessionListEntry, 0)
	for _, s := range h.mgr.ListForAccount(c.accountID) {
		mode := "observer"
		if c.hasControl(s.SessionID) {
			mode = "control"
		}
		entries = append(entries, sessionListEntry{
			SessionID: s.SessionID, EndpointID: s.EndpointID, Status: string(s.Status),
			CreatedAt: s.CreatedAt.UTC().Format(isoMillis), Source: string(s.Source), Mode: mode,
		})
	}
	return map[string]any{"type": "sessions:changed", "sessions": entries}
}

// Serve runs the read loop for an accepted connection until it closes.
func (h *Hub) Serve(ctx context.Context, wsc *websocket.Conn, accountID string) {
	c := newConn(wsc, accountID)
	h.add(c)
	defer h.remove(c)

	writerDone := c.startWriter(ctx)
	defer func() { c.close(); <-writerDone }()

	// Connect-time session list (scoped to this account).
	c.send(h.sessionList(c))

	for {
		_, raw, err := wsc.Read(ctx)
		if err != nil {
			return
		}
		msg := parseClientMessage(raw)
		if msg == nil {
			c.send(map[string]any{"type": "error", "message": "Invalid message format"})
			continue
		}
		h.route(c, msg)
	}
}

const isoMillis = "2006-01-02T15:04:05.000Z"
