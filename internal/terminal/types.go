// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Terminal session types (port of terminal/types.ts).
package terminal

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Status is a session's lifecycle state.
type Status string

const (
	StatusOpening Status = "opening"
	StatusOpen    Status = "open"
	StatusClosing Status = "closing"
	StatusClosed  Status = "closed"
	StatusError   Status = "error"
)

// Source is where a session originated.
type Source string

const (
	SourceUI  Source = "ui"
	SourceMCP Source = "mcp"
	SourceSSH Source = "ssh"
)

// CloseReason records why a session ended (CloseReason in types.ts).
type CloseReason string

const (
	CloseClientUI        CloseReason = "client.ui"
	CloseClientMCP       CloseReason = "client.mcp"
	CloseClientWS        CloseReason = "client.ws"
	CloseAgentDisconnect CloseReason = "agent-disconnect"
	CloseIdleTimeout     CloseReason = "idle-timeout"
	CloseAccountDeleted  CloseReason = "account-deleted"
	CloseServerHangup    CloseReason = "server-hangup"
	CloseTransportError  CloseReason = "transport-error"
	CloseShutdown        CloseReason = "shutdown"
)

// Session is a terminal session (TerminalSession). Time fields serialize as
// ISO strings via the DTO in the REST layer.
type Session struct {
	SessionID      string
	EndpointID     string
	AccountID      string
	Status         Status
	CreatedAt      time.Time
	LastActivityAt time.Time
	Source         Source
	CloseReason    CloseReason
	SourceIP       string
	MCPReason      string
	MCPClientName  string
	MCPClientVer   string
}

// Trigger carries create-time metadata (EndpointAuthTrigger subset).
type Trigger struct {
	Kind          Source
	SourceIP      string
	Reason        string
	MCPClientName string
	MCPClientVer  string
}

// GenerateSessionID returns a "sess_<12 hex>" id (generateSessionId()).
func GenerateSessionID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "sess_" + hex.EncodeToString(b[:])
}

var _ = time.Now
