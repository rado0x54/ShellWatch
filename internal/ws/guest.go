// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Guest WebSocket (/ws/guest, #306): the connection a ticket guest's
// browser holds while it waits for admission and then uses as its terminal.
// The guest cookie is the only credential. Guest connections reuse the
// per-connection machinery of the account hub (conn: writer queue, flushMu
// ordering, attach catch-up) but live in their own registry: they are never
// in Hub.conns, so SendToAccount, session-list broadcasts and sign requests
// cannot reach them — isolation by construction, not by filter. The
// connection *is* the attachment; there are no attach/detach messages.
package ws

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/rado0x54/shellwatch/internal/apierr"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/realip"
	"github.com/rado0x54/shellwatch/internal/terminal"
	"github.com/rado0x54/shellwatch/internal/ticket"
)

// MaxGuestInboundMessageBytes caps one client→server guest frame.
const MaxGuestInboundMessageBytes = 1 << 20

// GuestService is the ticket-service surface the guest hub drives
// (satisfied by *ticket.Service).
type GuestService interface {
	GuestByCookie(cookie string) (string, bool)
	Attach(guestID string) error
	Detach(guestID string)
	End(guestID string)
	Retry(guestID string)
}

// GuestHub owns every guest connection, keyed by guest session.
type GuestHub struct {
	mgr         *terminal.Manager
	svc         GuestService
	externalURL func() string

	mu    sync.Mutex
	conns map[string]map[*guestConn]struct{}
	// guestBySession maps an admitted terminal session to its guest session,
	// so output is routed without scanning every guest connection.
	guestBySession map[string]string

	unsubOutput  func()
	unsubRemoved func()
}

type guestConn struct {
	*conn
	guestID    string
	writerDone <-chan struct{}
	finishOnce sync.Once
}

// GuestHubParams configure the guest hub.
type GuestHubParams struct {
	Manager *terminal.Manager
	Service GuestService
	// ExternalURL yields server.externalUrl, the only accepted Origin.
	ExternalURL func() string
}

// NewGuestHub wires the guest hub to the Manager's output notifier.
func NewGuestHub(p GuestHubParams) *GuestHub {
	h := &GuestHub{mgr: p.Manager, svc: p.Service, externalURL: p.ExternalURL, conns: map[string]map[*guestConn]struct{}{}, guestBySession: map[string]string{}}
	h.unsubOutput = p.Manager.SubscribeOutput(h.onOutput)
	h.unsubRemoved = p.Manager.SubscribeRemoved(h.onRemoved)
	return h
}

// Close detaches the hub's manager subscriptions.
func (h *GuestHub) Close() {
	h.unsubOutput()
	h.unsubRemoved()
}

func (h *GuestHub) snapshot(guestID string) []*guestConn {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*guestConn, 0, len(h.conns[guestID]))
	for c := range h.conns[guestID] {
		out = append(out, c)
	}
	return out
}

func (h *GuestHub) all() []*guestConn {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []*guestConn
	for _, set := range h.conns {
		for c := range set {
			out = append(out, c)
		}
	}
	return out
}

// statusFrame is a guest status message: the Status fields plus its type.
func statusFrame(st ticket.Status) []byte {
	out, _ := json.Marshal(struct {
		Type string `json:"type"`
		ticket.Status
	}{"status", st})
	return out
}

// GuestStatus implements ticket.Publisher.
func (h *GuestHub) GuestStatus(guestID string, st ticket.Status) {
	raw := statusFrame(st)
	for _, c := range h.snapshot(guestID) {
		c.enqueue(raw)
	}
}

// GuestOpen implements ticket.Publisher: bind every not-yet-bound
// connection of the guest to its admitted session, with the full buffered
// output as catch-up.
func (h *GuestHub) GuestOpen(guestID, sessionID string) {
	for _, c := range h.snapshot(guestID) {
		h.bind(c, sessionID)
	}
}

func (h *GuestHub) bind(c *guestConn, sessionID string) {
	if c.isAttached(sessionID) {
		return
	}
	h.mu.Lock()
	h.guestBySession[sessionID] = c.guestID
	h.mu.Unlock()
	buffered, err := h.mgr.ReadOutputFrom(sessionID, nil)
	if err != nil {
		// The session is already gone; its closed event ends the guest
		// session (and this connection) through the ticket service.
		slog.Warn("ws: guest bind failed", "session", sessionID, "err", err)
		return
	}
	// The catch-up is always the whole buffer with reset: a reconnecting
	// page (dropped socket, no reload) clears what it showed before.
	frames := [][]byte{marshalFrame(outputFrame(outputFrameParams{
		guest: true, sessionID: sessionID, data: buffered.Data, offset: buffered.Offset, reset: true,
	}))}
	c.attachWithCatchUp(sessionID, true, buffered.Offset, frames)
	c.flushOutput(h.mgr, sessionID)
}

// GuestClose implements ticket.Publisher: the output still pending for the
// guest's session, then the final status, then every connection closes once
// its queue has drained. The flush mirrors the account hub's closeSession: a
// session that ends on the remote side (logout, the last command's result)
// emits its tail right before closing, and the guest must see it too. It
// runs inside the Manager's closed-status hook, before the session is
// removed, so the buffer is still readable.
func (h *GuestHub) GuestClose(guestID string, st ticket.Status) {
	raw := statusFrame(st)
	h.mu.Lock()
	for sid, gid := range h.guestBySession {
		if gid == guestID {
			delete(h.guestBySession, sid)
		}
	}
	h.mu.Unlock()
	for _, c := range h.snapshot(guestID) {
		for _, sid := range c.attachedIDs() {
			c.flushOutput(h.mgr, sid)
		}
		c.enqueue(raw)
		c.finish()
	}
}

// finish closes the outbound queue, lets the writer drain it (so the final
// status frame arrives), then closes the socket — which ends the read loop.
func (c *guestConn) finish() {
	c.finishOnce.Do(func() {
		c.mu.Lock()
		if !c.closed {
			c.closed = true
			close(c.out)
		}
		c.mu.Unlock()
		go func() {
			select {
			case <-c.writerDone:
			case <-time.After(5 * time.Second):
			}
			_ = c.ws.Close(websocket.StatusNormalClosure, "")
		}()
	})
}

func (h *GuestHub) onOutput(sessionID string, _ int64) {
	h.mu.Lock()
	guestID, ok := h.guestBySession[sessionID]
	h.mu.Unlock()
	if !ok {
		return // not a guest's session: the common case, no scan
	}
	for _, c := range h.snapshot(guestID) {
		if c.isAttached(sessionID) {
			c.flushOutput(h.mgr, sessionID)
		}
	}
}

// onRemoved drops a removed session's binding (its output is gone); the
// ticket service's status hook closes the guest session itself.
func (h *GuestHub) onRemoved(ev terminal.RemovedEvent) {
	sessionID := ev.SessionID
	h.mu.Lock()
	delete(h.guestBySession, sessionID)
	h.mu.Unlock()
	for _, c := range h.all() {
		if c.isAttached(sessionID) {
			c.detach(sessionID)
		}
	}
}

// Handler is the /ws/guest upgrade handler. It is gate-exempt: the guest
// cookie is the only credential, and no principal ever enters this
// context. The Origin check runs before anything else.
func (h *GuestHub) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := realip.FromRequest(r)
		origin := r.Header.Get("Origin")
		if !auth.OriginAllowed(h.externalURL(), origin) {
			slog.Warn("ws: guest origin rejected", "sourceIp", ip, "origin", auth.OriginHost(origin),
				"expected", auth.OriginHost(h.externalURL()))
			apierr.Write(w, http.StatusForbidden, "Forbidden")
			return
		}
		var cookie string
		if ck, err := r.Cookie(ticket.CookieName); err == nil {
			cookie = ck.Value
		}
		guestID, ok := h.svc.GuestByCookie(cookie)
		if !ok {
			slog.Info("ws: guest rejected", "sourceIp", ip, "reason", "no live guest session for cookie")
			apierr.Write(w, http.StatusNotFound, "Not found")
			return
		}
		wsc, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// The exact-origin check above is authoritative; this pattern only
			// stops the library's Host comparison from refusing a correct
			// Origin behind a proxy that rewrites Host. It is the validated
			// origin itself, glob-escaped — never a wildcard.
			OriginPatterns: []string{globEscape(strings.ToLower(origin))},
		})
		if err != nil {
			return
		}
		wsc.SetReadLimit(MaxGuestInboundMessageBytes)
		start := time.Now()
		err = h.serve(r.Context(), wsc, guestID)
		slog.Info("ws: guest disconnected", "sourceIp", ip, "dur", time.Since(start).Round(time.Second),
			"reason", disconnectReason(err))
	}
}

func globEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '*', '?', '[', ']', '\\':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// guestMessage is a parsed inbound guest frame.
type guestMessage struct {
	Type string `json:"type"`
	Data string `json:"data"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

func (h *GuestHub) serve(ctx context.Context, wsc *websocket.Conn, guestID string) error {
	c := &guestConn{conn: newConn(wsc, ""), guestID: guestID}
	c.guest = true
	c.writerDone = c.startWriter(ctx)
	defer func() {
		c.finish()
		<-c.writerDone
	}()

	// Register before Attach: the status Attach publishes must reach this
	// connection.
	h.mu.Lock()
	if h.conns[guestID] == nil {
		h.conns[guestID] = map[*guestConn]struct{}{}
	}
	h.conns[guestID][c] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.conns[guestID], c)
		if len(h.conns[guestID]) == 0 {
			delete(h.conns, guestID)
		}
		h.mu.Unlock()
	}()

	if err := h.svc.Attach(guestID); err != nil {
		msg := ticket.MsgNotGranted
		if err == ticket.ErrTooManyConnections {
			msg = "Too many open windows for this session."
		}
		c.enqueue(statusFrame(ticket.Status{
			State: ticket.StateClosed, Message: msg, ServerTime: time.Now().UTC().Format(clock.ISOMillis),
		}))
		c.finish()
		_, _, rerr := wsc.Read(ctx)
		return rerr
	}
	defer h.svc.Detach(guestID)

	for {
		_, raw, err := wsc.Read(ctx)
		if err != nil {
			return err
		}
		var msg guestMessage
		if json.Unmarshal(raw, &msg) != nil {
			continue
		}
		h.route(c, &msg)
	}
}

// route accepts only input, resize, end and retry — always for the guest's
// own session. Everything else is dropped.
func (h *GuestHub) route(c *guestConn, msg *guestMessage) {
	switch msg.Type {
	case "input":
		if sid := c.boundSession(); sid != "" {
			_ = h.mgr.SendInput(sid, msg.Data)
		}
	case "resize":
		if sid := c.boundSession(); sid != "" && msg.Cols > 0 && msg.Rows > 0 {
			_ = h.mgr.Resize(sid, msg.Cols, msg.Rows)
		}
	case "end":
		h.svc.End(c.guestID)
	case "retry":
		h.svc.Retry(c.guestID)
	}
}

// boundSession is the one session this connection is attached to ("" before
// admission).
func (c *guestConn) boundSession() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for sid, ok := range c.attached {
		if ok {
			return sid
		}
	}
	return ""
}
