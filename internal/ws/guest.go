// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Guest WebSocket (/ws/guest, #306, #328): the connection a ticket guest's
// browser holds while it waits for admission and then uses as its terminal.
// The guest cookie is the only credential. A guest connection is an ordinary
// hub connection with a guest scope: no account id (so SendToAccount,
// session-list broadcasts and sign requests cannot match it), attached only
// by the hub to its guest's terminal session, and its read loop accepts only
// terminal:input / terminal:resize for that session plus end. It speaks the
// /ws terminal frames; the one guest-specific frame is status.
package ws

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/rado0x54/shellwatch/internal/apierr"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/realip"
	"github.com/rado0x54/shellwatch/internal/ticket"
)

// MaxGuestInboundMessageBytes caps one client→server guest frame.
const MaxGuestInboundMessageBytes = 1 << 20

// GuestService is the ticket-service surface the hub drives for guests
// (satisfied by *ticket.Service).
type GuestService interface {
	GuestByCookie(cookie string) (string, bool)
	Attach(guestID string) error
	Detach(guestID string)
	End(guestID string)
}

// GuestParams enable the guest route on the hub.
type GuestParams struct {
	Service GuestService
	// ExternalURL yields server.externalUrl, the only accepted Origin.
	ExternalURL func() string
}

// EnableGuests wires the ticket service (set once at the composition root,
// before /ws/guest serves). The hub is then the service's ticket.Publisher.
func (h *Hub) EnableGuests(p GuestParams) {
	h.mu.Lock()
	h.guests = p
	h.mu.Unlock()
}

// guestConns lists the open connections of one guest session.
func (h *Hub) guestConns(guestID string) []*conn {
	return h.snapshot(func(c *conn) bool { return c.guestID == guestID })
}

// statusFrame is a guest status message: the Status fields plus its type.
func statusFrame(st ticket.Status) []byte {
	out, _ := json.Marshal(struct {
		Type string `json:"type"`
		ticket.Status
	}{"status", st})
	return out
}

// closedFrame is a final closed status sent outside the ticket service.
func closedFrame(msg string) []byte {
	return statusFrame(ticket.Status{State: ticket.StateClosed, Message: msg, ServerTime: time.Now().UTC().Format(clock.ISOMillis)})
}

// GuestStatus implements ticket.Publisher.
func (h *Hub) GuestStatus(guestID string, st ticket.Status) {
	raw := statusFrame(st)
	for _, c := range h.guestConns(guestID) {
		c.enqueue(raw)
	}
}

// GuestOpen implements ticket.Publisher: attach every not-yet-attached
// connection of the guest to its admitted session. The catch-up is always
// the whole buffer with reset, so a reconnecting page (dropped socket, no
// reload) clears what it showed before.
func (h *Hub) GuestOpen(guestID, sessionID string) {
	for _, c := range h.guestConns(guestID) {
		if c.isAttached(sessionID) {
			continue
		}
		buffered, err := h.mgr.ReadOutputFrom(sessionID, nil)
		if err != nil {
			// Already gone: its closed event ends the guest session (and this
			// connection) through the ticket service.
			slog.Warn("ws: guest attach failed", "session", sessionID, "err", err)
			return
		}
		frame := marshalFrame(outputFrame(sessionID, buffered.Data, buffered.Offset, true))
		c.attachWithCatchUp(sessionID, true, buffered.Offset, [][]byte{frame})
		c.flushOutput(h.mgr, sessionID)
	}
}

// GuestClose implements ticket.Publisher: the session's pending output and
// terminal:closed (a session that ends on the remote side emits its tail
// right before closing), then the final status, then every connection
// closes once its queue has drained. It runs inside the Manager's
// closed-status hook, before the session is removed, so the buffer is still
// readable.
func (h *Hub) GuestClose(guestID string, st ticket.Status) {
	raw := statusFrame(st)
	for _, c := range h.guestConns(guestID) {
		for _, sid := range c.attachedIDs() {
			c.closeSession(h.mgr, sid)
		}
		c.enqueue(raw)
		c.finish()
	}
}

// finish closes the outbound queue, lets the writer drain it (so the final
// status frame arrives), then closes the socket — which ends the read loop.
func (c *conn) finish() {
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

// GuestHandler is the /ws/guest upgrade handler. It is gate-exempt: the
// guest cookie is the only credential, and no principal ever enters this
// context. The Origin check runs before anything else.
func (h *Hub) GuestHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		g := h.guests
		h.mu.Unlock()
		ip := realip.FromRequest(r)
		origin := r.Header.Get("Origin")
		if g.Service == nil {
			slog.Error("ws: guest route without a ticket service")
			apierr.Write(w, http.StatusNotFound, "Not found")
			return
		}
		if !auth.OriginAllowed(g.ExternalURL(), origin) {
			slog.Warn("ws: guest origin rejected", "sourceIp", ip, "origin", auth.OriginHost(origin),
				"expected", auth.OriginHost(g.ExternalURL()))
			apierr.Write(w, http.StatusForbidden, "Forbidden")
			return
		}
		var cookie string
		if ck, err := r.Cookie(ticket.CookieName); err == nil {
			cookie = ck.Value
		}
		guestID, ok := g.Service.GuestByCookie(cookie)
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
		if !ok {
			// Ended, revoked or never existed: indistinguishable, and the page
			// is told so in a frame (a refused handshake's status is invisible
			// to a browser, which would keep reconnecting). No per-cookie state
			// survives a guest session, and an unknown cookie never reaches
			// Attach.
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			_ = wsc.Write(ctx, websocket.MessageText, closedFrame(ticket.MsgEnded))
			cancel()
			_ = wsc.Close(websocket.StatusNormalClosure, "")
			slog.Info("ws: guest rejected", "sourceIp", ip, "reason", "no live guest session for cookie")
			return
		}
		start := time.Now()
		err = h.serveGuest(r.Context(), wsc, g.Service, guestID)
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

func (h *Hub) serveGuest(ctx context.Context, wsc *websocket.Conn, svc GuestService, guestID string) error {
	c := newConn(wsc, "")
	c.guestID = guestID
	c.writerDone = c.startWriter(ctx)
	defer func() {
		c.finish()
		<-c.writerDone
	}()
	// Register before Attach: the status Attach publishes must reach this
	// connection.
	h.add(c)
	defer h.remove(c)

	if err := svc.Attach(guestID); err != nil {
		msg := ticket.MsgEnded
		if err == ticket.ErrTooManyConnections {
			msg = "Too many open windows for this session."
		}
		c.enqueue(closedFrame(msg))
		c.finish()
		_, _, rerr := wsc.Read(ctx)
		return rerr
	}
	defer svc.Detach(guestID)

	for {
		_, raw, err := wsc.Read(ctx)
		if err != nil {
			return err
		}
		if msg := parseClientMessage(raw); msg != nil {
			h.routeGuest(c, svc, msg)
		}
	}
}

// routeGuest accepts only input and resize for the session the hub attached
// this connection to, and end. Everything else is dropped without an answer.
func (h *Hub) routeGuest(c *conn, svc GuestService, msg *clientMessage) {
	switch msg.Type {
	case "terminal:input":
		if c.isAttached(msg.SessionID) {
			_ = h.mgr.SendInput(msg.SessionID, msg.Data)
		}
	case "terminal:resize":
		if c.isAttached(msg.SessionID) && msg.Cols > 0 && msg.Rows > 0 {
			_ = h.mgr.Resize(msg.SessionID, msg.Cols, msg.Rows)
		}
	case "end":
		svc.End(c.guestID)
	}
}
