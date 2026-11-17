// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Terminal session types (port of terminal/types.ts).
package terminal

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
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
	// SourceTicket is a guest session admitted through a one-time access
	// ticket (#306). Its channel (web, later ssh) rides on the trigger.
	SourceTicket Source = "ticket"
)

// TicketChannel is how a ticket was redeemed (#306: web; #307: ssh).
type TicketChannel string

const TicketChannelWeb TicketChannel = "web"

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

	// Guest-session end reasons (#306). The ticket service is the only
	// producer; those that end a terminal session are also its close reason.
	CloseClientGuest       CloseReason = "client.guest"
	CloseGuestDisconnected CloseReason = "guest-disconnected"
	CloseTicketLifetime    CloseReason = "ticket-lifetime"
	CloseTicketNotAdmitted CloseReason = "ticket-not-admitted"
	CloseTicketUnattached  CloseReason = "ticket-unattached"
	CloseTicketRevoked     CloseReason = "ticket-revoked"
	CloseEndpointRemoved   CloseReason = "endpoint-removed"
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
	Origin
	// Deadline is the hard end of an open session (zero when none) and
	// DeadlineReason the close reason it ends with (Trigger.Lifetime).
	Deadline       time.Time
	DeadlineReason CloseReason
}

// Origin is what a session keeps of the trigger that opened it. Trigger and
// Session share it and Manager.Create copies it whole; each producer sets
// only its own source's fields.
type Origin struct {
	// OwnerClientID is the OAuth client that created the session (MCP source
	// only). MCP ownership is (AccountID, OwnerClientID) — the spec's
	// server-minted-handle model, #243.
	OwnerClientID string
	// Reason is self-reported (an MCP agent's or a ticket guest's — Source
	// tells which, #319).
	Reason        string
	MCPClientName string
	MCPClientVer  string
	// Ticket fields (source ticket only, #306).
	TicketID      string
	TicketLabel   string
	TicketChannel TicketChannel
}

// Trigger carries create-time metadata (EndpointAuthTrigger subset).
type Trigger struct {
	Kind     Source
	SourceIP string
	Origin
	// SessionID pre-assigns the session id (optional): the ticket service
	// must recognize its session's status events, including the closed
	// broadcast of a failed create that never returns a session.
	SessionID string
	// Lifetime > 0 is a hard cap counted from when the session goes open
	// (Session.Deadline); the Manager's janitor closes it then with
	// LifetimeReason.
	Lifetime       time.Duration
	LifetimeReason CloseReason
	// Ticket is set for source ticket (#306): what the approval prompt shows.
	Ticket *TicketTrigger
	// MaxActive > 0 refuses the create with a *LimitError when the account
	// already has that many active (opening or open) sessions of any source.
	// Checked under the registry lock, so concurrent creates cannot overshoot.
	MaxActive int
}

// LimitError: the account is at its max_sessions.
type LimitError struct{ Max int }

func (e *LimitError) Error() string {
	return fmt.Sprintf("Maximum concurrent sessions (%d) reached", e.Max)
}

// TicketTrigger is the ticket context of a guest session's create (#306).
// It and the ticket fields of Trigger.Origin are shown on the approval
// prompt; UserAgent and the reason (Trigger.Reason) are self-reported by the
// guest.
type TicketTrigger struct {
	UserAgent        string
	ConfirmationCode string
	AgentForward     bool
	LifetimeSeconds  int
	// Target is the endpoint target the ticket was minted for
	// (EndpointRef.Target); Open refuses to connect anywhere else.
	Target string
}

// SessionViews builds the session fields REST (TerminalSession) and the
// WebSocket (sessions:changed) share. Shapes are frozen by docs/api/.
type SessionViews struct {
	// GuestAttached reports whether a ticket guest is attached to a session
	// (#306; ok=false for any other session or once the guest session is
	// over). nil -> never.
	GuestAttached func(sessionID string) (attached, ok bool)
}

// SessionView is one session as both REST and the WebSocket show it.
type SessionView struct {
	SessionID  string `json:"sessionId"`
	EndpointID string `json:"endpointId"`
	Status     string `json:"status"`
	CreatedAt  string `json:"createdAt"`
	Source     string `json:"source"`
	// Ticket guest sessions only (#306). GuestAttached is present only while
	// the guest session is live, so a client can tell "guest away" (false)
	// from "guest session over" (absent).
	TicketID      string  `json:"ticketId,omitempty"`
	TicketLabel   *string `json:"ticketLabel,omitempty"`
	GuestAttached *bool   `json:"guestAttached,omitempty"`
}

// View builds s's shared fields.
func (v SessionViews) View(s Session) SessionView {
	out := SessionView{
		SessionID: s.SessionID, EndpointID: s.EndpointID, Status: string(s.Status),
		CreatedAt: s.CreatedAt.UTC().Format(clock.ISOMillis), Source: string(s.Source),
	}
	if s.Source == SourceTicket {
		label := s.TicketLabel
		out.TicketID, out.TicketLabel = s.TicketID, &label
		if v.GuestAttached != nil {
			if attached, ok := v.GuestAttached(s.SessionID); ok {
				out.GuestAttached = &attached
			}
		}
	}
	return out
}

// GenerateSessionID returns a "sess_<12 hex>" id (generateSessionId()).
func GenerateSessionID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "sess_" + hex.EncodeToString(b[:])
}
