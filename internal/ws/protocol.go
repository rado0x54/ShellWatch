// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// WebSocket message types (port of src/server/ws-protocol.ts). Shapes are
// frozen by docs/api/websocket-protocol.md and the ws-* goldens.
package ws

import (
	"encoding/json"

	"github.com/rado0x54/shellwatch/internal/terminal"
)

// clientMessage is a parsed inbound frame (only the fields any handler reads).
type clientMessage struct {
	Type        string `json:"type"`
	SessionID   string `json:"sessionId"`
	Data        string `json:"data"`
	Cols        int    `json:"cols"`
	Rows        int    `json:"rows"`
	AfterOffset *int64 `json:"afterOffset"`
}

// parseClientMessage returns nil for unparseable / typeless frames
// (parseClientMessage in ws-protocol.ts).
func parseClientMessage(raw []byte) *clientMessage {
	var m clientMessage
	if err := json.Unmarshal(raw, &m); err != nil || m.Type == "" {
		return nil
	}
	return &m
}

// sessionListEntry is one row of sessions:changed (SessionListEntry): the
// session view shared with REST plus this connection's mode. source is a
// bare string on the wire (contract item H, preserved).
type sessionListEntry struct {
	terminal.SessionView
	Mode string `json:"mode"`
}
