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

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// Hub owns all browser connections.
type Hub struct {
	mgr *terminal.Manager

	mu    sync.Mutex
	conns map[*conn]struct{}

	unsubStatus     func()
	unsubOutput     func()
	unsubRemoved    func()
	unsubRegistered func()

	// fileSnapshot delivers a terminal:file frame per unfinished file
	// transfer of a session (#263), so a (re)attaching client reconstructs
	// the transfer strip. It is called AFTER the connection is attached and
	// must hold back live terminal:file frames while deliver runs, so no
	// frame is lost between the snapshot and the attach. nil -> none.
	fileSnapshot func(sessionID string, deliver func(frames []any))

	// views builds the session-list rows (shared with REST).
	views terminal.SessionViews

	// guests enables /ws/guest (#328); zero -> no guest route.
	guests GuestParams
}

// snapshot copies the connections matching keep (nil -> all), so fan-out
// runs without the hub lock.
func (h *Hub) snapshot(keep func(*conn) bool) []*conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*conn, 0, len(h.conns))
	for c := range h.conns {
		if keep == nil || keep(c) {
			out = append(out, c)
		}
	}
	return out
}

// owner selects an account's own connections (never a guest's).
func owner(accountID string) func(*conn) bool {
	return func(c *conn) bool { return c.ownedBy(accountID) }
}

// SetSessionViews wires the session view shared with REST (set once at the
// composition root).
func (h *Hub) SetSessionViews(v terminal.SessionViews) {
	h.mu.Lock()
	h.views = v
	h.mu.Unlock()
}

// TicketsChanged tells the account's browsers to refetch GET /api/tickets
// (#306).
func (h *Hub) TicketsChanged(accountID string) {
	h.SendToAccount(accountID, map[string]any{"type": "tickets:changed"})
}

// SessionsChanged re-sends the account's session list (a guest attached or
// detached, #306).
func (h *Hub) SessionsChanged(accountID string) {
	h.onRegistered("", accountID)
}

// SetFileSnapshot wires the file-transfer snapshot source (set once at the
// composition root, before the hub serves connections).
func (h *Hub) SetFileSnapshot(fn func(sessionID string, deliver func(frames []any))) {
	h.mu.Lock()
	h.fileSnapshot = fn
	h.mu.Unlock()
}

// SendToSession delivers a server message to every account connection
// currently attached to a session (terminal:file fan-out, #263). Attach is
// account-checked; a guest is attached to its session too, so it is
// excluded explicitly (#328).
func (h *Hub) SendToSession(sessionID string, msg any) {
	raw, err := json.Marshal(msg)
	if err != nil {
		return
	}
	for _, c := range h.snapshot(func(c *conn) bool { return !c.isGuest() }) {
		if c.isAttached(sessionID) {
			c.enqueue(raw)
		}
	}
}

// NewHub wires the hub to the terminal manager's guaranteed status hook and
// coalesced output notifier.
func NewHub(mgr *terminal.Manager) *Hub {
	h := &Hub{mgr: mgr, conns: map[*conn]struct{}{}}
	h.unsubStatus = mgr.SubscribeStatus(h.onStatusChange)
	h.unsubOutput = mgr.SubscribeOutput(h.onOutput)
	h.unsubRemoved = mgr.SubscribeRemoved(h.onRemoved)
	h.unsubRegistered = mgr.SubscribeRegistered(h.onRegistered)
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
	if h.unsubRegistered != nil {
		h.unsubRegistered()
	}
	if h.unsubRemoved != nil {
		h.unsubRemoved()
	}
}

// onRegistered sends the owning account's connections a sessions:changed that
// lists a session still connecting (status opening), so a browser approving
// its SSH signature can open the session's page right away (#273).
func (h *Hub) onRegistered(_, accountID string) {
	for _, c := range h.snapshot(owner(accountID)) {
		c.send(h.sessionList(c))
	}
}

// onRemoved sweeps every connection still attached to a session the Manager
// just removed from its registry: an attach can land between the Closed
// broadcast and the delete (the broadcast must come first so the tail drain
// can read the buffer), and such a connection would otherwise stay attached
// forever without a terminal:closed. closeSession no-ops when not attached.
// For a silent removal (expiry, eviction) it also resends the owning
// account's connections their session list.
func (h *Hub) onRemoved(ev terminal.RemovedEvent) {
	for _, c := range h.snapshot(nil) {
		if c.isAttached(ev.SessionID) { // cheap prefilter: don't take flushMu on bystanders
			c.closeSession(h.mgr, ev.SessionID)
		}
		// A silent removal (a retained ended session expired or evicted) is
		// a list change nothing else announces: an errored session is listed
		// until then. Only the owning account's connections need the list.
		if ev.Reason.Silent() && c.ownedBy(ev.AccountID) {
			c.send(h.sessionList(c))
		}
	}
}

// SendToAccount delivers a server message to every connection owned by an
// account (the narrow seam the approval layer uses in Phase 4).
func (h *Hub) SendToAccount(accountID string, msg any) {
	raw, err := json.Marshal(msg)
	if err != nil {
		return
	}
	for _, c := range h.snapshot(owner(accountID)) {
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
// account connection, plus terminal:closed to connections attached to a
// now-closed session (the Node onClose behavior; guests included). Low-
// frequency, so not coalesced.
func (h *Hub) onStatusChange(ev terminal.StatusEvent) {
	terminalState := ev.Status == terminal.StatusClosed || ev.Status == terminal.StatusError
	for _, c := range h.snapshot(nil) {
		if terminalState {
			c.closeSession(h.mgr, ev.SessionID)
		}
		if !c.isGuest() {
			c.send(h.sessionList(c))
		}
	}
}

// onOutput delivers the coalesced delta to attached connections.
func (h *Hub) onOutput(sessionID string, _ int64) {
	for _, c := range h.snapshot(nil) {
		if c.isAttached(sessionID) {
			c.flushOutput(h.mgr, sessionID)
		}
	}
}

// sessionList builds an account-scoped sessions:changed for a connection
// (buildSessionList in ws-message-router.ts).
func (h *Hub) sessionList(c *conn) map[string]any {
	entries := make([]sessionListEntry, 0)
	h.mu.Lock()
	views := h.views
	h.mu.Unlock()
	for _, s := range h.mgr.ListForAccount(c.accountID) {
		mode := "observer"
		if c.hasControl(s.SessionID) {
			mode = "control"
		}
		entries = append(entries, sessionListEntry{SessionView: views.View(s), Mode: mode})
	}
	return map[string]any{"type": "sessions:changed", "sessions": entries}
}

// Serve runs the read loop for an accepted connection until it closes and
// returns the read error that ended it (for the disconnect log line).
func (h *Hub) Serve(ctx context.Context, wsc *websocket.Conn, accountID string) error {
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
			return err
		}
		msg := parseClientMessage(raw)
		if msg == nil {
			c.send(map[string]any{"type": "error", "message": "Invalid message format"})
			continue
		}
		h.route(c, msg)
	}
}

const isoMillis = clock.ISOMillis
