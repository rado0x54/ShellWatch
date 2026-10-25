// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package agentproxy is the /agent-proxy WS bridge (port of src/agent-socket/,
// frozen in docs/api/agent-proxy-protocol.md): it runs the SSH agent protocol
// over WebSocket for the Go agent-client. Each binary WS message is one
// complete agent frame (4-byte BE length + payload); every sign — passkey and
// file key — is routed through the pending-action broker (human-in-the-loop).
package agentproxy

import (
	"context"
	"encoding/binary"
	"io"

	"github.com/coder/websocket"
)

// wsReadWriter adapts a coder/websocket.Conn to the io.ReadWriter that
// agent.ServeAgent needs. Reads stream bytes from one binary message at a
// time; writes coalesce into whole agent frames so each response is exactly
// one binary WS message (the client reads one message per response).
type wsReadWriter struct {
	ctx context.Context
	ws  *websocket.Conn

	readBuf  []byte // remaining bytes of the current inbound message
	writeBuf []byte // accumulates outbound bytes until a full frame is present
}

func newWSReadWriter(ctx context.Context, ws *websocket.Conn) *wsReadWriter {
	return &wsReadWriter{ctx: ctx, ws: ws}
}

func (c *wsReadWriter) Read(p []byte) (int, error) {
	for len(c.readBuf) == 0 {
		typ, data, err := c.ws.Read(c.ctx)
		if err != nil {
			return 0, err
		}
		if typ != websocket.MessageBinary {
			// Only binary messages are accepted (close code 4002 in the doc).
			c.ws.Close(4002, "Only binary messages are accepted")
			return 0, io.EOF
		}
		c.readBuf = data
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// Write buffers outbound bytes and flushes one WS message per complete agent
// frame (4-byte length prefix + payload), regardless of how ServeAgent chunks
// its writes.
func (c *wsReadWriter) Write(p []byte) (int, error) {
	c.writeBuf = append(c.writeBuf, p...)
	for len(c.writeBuf) >= 4 {
		n := binary.BigEndian.Uint32(c.writeBuf[:4])
		if uint32(len(c.writeBuf)-4) < n {
			break // frame not complete yet
		}
		frame := c.writeBuf[:4+n]
		if err := c.ws.Write(c.ctx, websocket.MessageBinary, frame); err != nil {
			return 0, err
		}
		c.writeBuf = c.writeBuf[4+n:]
	}
	return len(p), nil
}
