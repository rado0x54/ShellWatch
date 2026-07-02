// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Terminal message routing (port of routeMessage in ws-message-router.ts).
// Control/observer semantics and the input-errors-loudly / resize-silent
// asymmetry are preserved exactly (docs/api/websocket-protocol.md).
package ws

import (
	"fmt"

	"github.com/rado0x54/shellwatch/internal/terminal"
)

func (h *Hub) route(c *conn, msg *clientMessage) {
	switch msg.Type {
	case "terminal:attach":
		h.attach(c, msg)
	case "terminal:detach":
		c.detach(msg.SessionID)
	case "terminal:input":
		h.input(c, msg)
	case "terminal:resize":
		h.resize(c, msg)
	case "terminal:close":
		h.closeSession(c, msg)
	case "terminal:take-control":
		h.takeControl(c, msg)
	case "terminal:release-control":
		h.releaseControl(c, msg)
	}
}

func (h *Hub) attach(c *conn, msg *clientMessage) {
	sess := h.mgr.GetSession(msg.SessionID)
	if sess == nil || sess.AccountID != c.accountID {
		c.sendError(fmt.Sprintf("Session not found: %s", msg.SessionID))
		return
	}
	// UI-created sessions default to control for the owning account; mcp/ssh
	// attach as observer (take-control to send input).
	control := sess.Source == terminal.SourceUI
	c.attach(msg.SessionID, control)
	mode := "observer"
	if c.hasControl(msg.SessionID) {
		mode = "control"
	}
	c.send(map[string]any{"type": "terminal:status", "sessionId": msg.SessionID, "status": string(sess.Status)})
	c.send(map[string]any{"type": "terminal:mode", "sessionId": msg.SessionID, "mode": mode})

	// Buffered catch-up: delta from afterOffset, or full buffer with reset.
	buffered, err := h.mgr.ReadOutputFrom(msg.SessionID, msg.AfterOffset)
	if err != nil {
		return
	}
	c.setInitialOffset(msg.SessionID, buffered.Offset)
	if len(buffered.Data) > 0 || buffered.Reset {
		out := map[string]any{
			"type": "terminal:output", "sessionId": msg.SessionID,
			"data": string(buffered.Data), "offset": buffered.Offset,
		}
		if buffered.Reset {
			out["reset"] = true
		}
		c.send(out)
	}
}

func (h *Hub) input(c *conn, msg *clientMessage) {
	if !c.isAttached(msg.SessionID) {
		c.sendError(fmt.Sprintf("Session not attached: %s", msg.SessionID))
		return
	}
	if !c.hasControl(msg.SessionID) {
		c.sendError("Observer mode: take control first to send input")
		return
	}
	if err := h.mgr.SendInput(msg.SessionID, msg.Data); err != nil {
		c.sendError(err.Error())
	}
}

func (h *Hub) resize(c *conn, msg *clientMessage) {
	// Silent when unattached or observer (resize fires on every layout change).
	if !c.isAttached(msg.SessionID) || !c.hasControl(msg.SessionID) {
		return
	}
	_ = h.mgr.Resize(msg.SessionID, msg.Cols, msg.Rows)
}

func (h *Hub) closeSession(c *conn, msg *clientMessage) {
	sess := h.mgr.GetSession(msg.SessionID)
	if sess == nil || sess.AccountID != c.accountID {
		c.sendError(fmt.Sprintf("Session not found: %s", msg.SessionID))
		return
	}
	h.mgr.Close(msg.SessionID, terminal.CloseClientWS)
}

func (h *Hub) takeControl(c *conn, msg *clientMessage) {
	sess := h.mgr.GetSession(msg.SessionID)
	if sess == nil || sess.AccountID != c.accountID {
		c.sendError(fmt.Sprintf("Session not found: %s", msg.SessionID))
		return
	}
	c.takeControl(msg.SessionID)
	c.send(map[string]any{"type": "terminal:mode", "sessionId": msg.SessionID, "mode": "control"})
}

func (h *Hub) releaseControl(c *conn, msg *clientMessage) {
	// Silent if not attached (mirrors detach/resize; ownership came via attach).
	if !c.isAttached(msg.SessionID) {
		return
	}
	c.releaseControl(msg.SessionID)
	c.send(map[string]any{"type": "terminal:mode", "sessionId": msg.SessionID, "mode": "observer"})
}
