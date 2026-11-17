// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Transport is the pluggable connection behind a session (port of
// terminal/transport.ts). Implemented by the SSH transport (Phase 3 slice 3);
// a mock backs the manager tests. Events are delivered on a channel that the
// session's pump goroutine ranges over (docs/go-backend-architecture.md §5.2).
package terminal

import (
	"context"
	"net"
	"strconv"

	"github.com/pkg/sftp"
)

// Event is one transport signal: output bytes, or a terminal close/error.
type Event struct {
	Data   []byte
	Err    error // non-nil => transport error
	Closed bool  // true => transport closed (server hangup)
}

// Transport is a terminal's underlying connection.
type Transport interface {
	Write(data []byte) error
	Resize(cols, rows int) error
	// Close MUST cause Events to terminate (deliver any final events, then
	// close the channel) promptly: Manager.Close joins the pump draining it,
	// bounded by closeJoinTimeout — a transport that wedges past the bound
	// degrades that close (tail possibly incomplete, pump goroutine leaked)
	// but must never be able to wedge every close path behind it.
	Close() error
	// Events yields transport events until the transport ends, then closes.
	Events() <-chan Event
}

// FileTransport is the optional file capability of a Transport (#263): an
// SFTP subsystem channel multiplexed over the session's already-approved SSH
// connection — no new signature, no new approval. The SSH transport
// implements it; the mock opts out.
type FileTransport interface {
	// OpenSFTP opens a NEW sftp channel on the session's connection. The
	// caller owns the client; closing it closes only that channel, never the
	// PTY. ctx bounds the channel setup and the SFTP version handshake.
	OpenSFTP(ctx context.Context) (*sftp.Client, error)
}

// Unwrapper is implemented by transports that decorate another transport
// (sshx's end-watch wrapper). Optional capabilities such as FileTransport are
// discovered through the chain, so a wrapper never hides them by accident.
type Unwrapper interface {
	Unwrap() Transport
}

// FactoryParams are passed to a TransportFactory.
type FactoryParams struct {
	Endpoint  EndpointRef
	SessionID string
	Trigger   Trigger
}

// EndpointRef is the connection info the transport needs (decoupled from
// store.Endpoint to avoid an import cycle).
type EndpointRef struct {
	ID               string
	Label            string
	AccountID        string
	Host             string
	Port             int
	Username         string
	UserVerification string
	AgentForward     bool
}

// Target is the address a session connects to (user@host:port). A ticket is
// bound to the target it was minted for (#326).
func (e EndpointRef) Target() string {
	return e.Username + "@" + net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
}

// TransportFactory establishes a transport for a session.
type TransportFactory func(ctx context.Context, p FactoryParams) (Transport, error)
