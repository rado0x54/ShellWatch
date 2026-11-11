// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Terminal message routing (port of routeMessage in ws-message-router.ts).
// Control/observer semantics and the input-errors-loudly / resize-silent
// asymmetry are preserved exactly (docs/api/websocket-protocol.md).
package ws

import (
	"encoding/json"
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
	// attach as observer (take-control to send input). hasControl is read
	// before the attach: only this read loop mutates control state, so a
	// re-attach keeps a previously taken control.
	control := sess.Source == terminal.SourceUI
	mode := "observer"
	if control || c.hasControl(msg.SessionID) {
		mode = "control"
	}

	// Buffered catch-up: delta from afterOffset, or full buffer with reset.
	buffered, err := h.mgr.ReadOutputFrom(msg.SessionID, msg.AfterOffset)
	if err != nil {
		// The session vanished between the GetSession check and the read
		// (explicit close): answer like the not-found path above instead of
		// leaving the terminal view hanging with no frame at all.
		c.sendError(fmt.Sprintf("Session not found: %s", msg.SessionID))
		return
	}
	frames := [][]byte{
		marshalFrame(map[string]any{"type": "terminal:status", "sessionId": msg.SessionID, "status": string(sess.Status)}),
		marshalFrame(map[string]any{"type": "terminal:mode", "sessionId": msg.SessionID, "mode": mode}),
	}
	if len(buffered.Data) > 0 || buffered.Reset {
		out := map[string]any{
			"type": "terminal:output", "sessionId": msg.SessionID,
			"data": string(buffered.Data), "offset": buffered.Offset,
		}
		if buffered.Reset {
			out["reset"] = true
		}
		frames = append(frames, marshalFrame(out))
	}
	c.attachWithCatchUp(msg.SessionID, control, buffered.Offset, frames)
	// Output appended between the buffer read above and the attach becoming
	// visible fired its onOutput before we were attached — pick it up now.
	c.flushOutput(h.mgr, msg.SessionID)
	// Re-check after the attach is visible: an explicit close that broadcast
	// terminal:closed before this attach landed has already notified every
	// attached connection. This catches an attach completing after the
	// registry delete; one completing between the broadcast and the delete is
	// swept by the Manager's removed hook (hub.onRemoved) instead. (An attach
	// to a closed-but-retained post-mortem session is legitimate and keeps
	// GetSession non-nil.)
	if h.mgr.GetSession(msg.SessionID) == nil {
		c.closeSession(h.mgr, msg.SessionID)
	}
}

func marshalFrame(msg any) []byte {
	raw, _ := json.Marshal(msg)
	return raw
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
