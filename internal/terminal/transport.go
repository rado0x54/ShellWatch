// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Transport is the pluggable connection behind a session (port of
// terminal/transport.ts). Implemented by the SSH transport (Phase 3 slice 3);
// a mock backs the manager tests. Events are delivered on a channel that the
// session's pump goroutine ranges over (docs/go-backend-architecture.md §5.2).
package terminal

import "context"

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
	Close() error
	// Events yields transport events until the transport ends, then closes.
	Events() <-chan Event
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
	AccountID        string
	Host             string
	Port             int
	Username         string
	UserVerification string
	AgentForward     bool
}

// TransportFactory establishes a transport for a session.
type TransportFactory func(ctx context.Context, p FactoryParams) (Transport, error)
