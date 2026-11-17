// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package endpointsvc is the shared endpoint read/resolution layer for REST,
// the agent session (MCP), and session creation. It owns the demo-endpoint
// merge rules and the field constraints both wire layers enforce — before it
// existed, the demo-aware resolution was hand-rolled three times and the
// validation constants twice, and the copies had already drifted once.
// Delete is shared by REST and MCP (#314): the active-session guard and the
// post-delete hooks must apply to both. Create/update still go straight to
// Endpoints from each wire layer (#315 moves them here too): demo entries are
// synthesized per request, never stored, and the wire layers reject demo ids
// before mutating.
package endpointsvc

import (
	"context"
	"errors"
	"log/slog"

	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// DescriptionMaxLen caps endpoint descriptions (REST and MCP alike).
const DescriptionMaxLen = 1000

// UserVerificationValues are the accepted userVerification policies.
var UserVerificationValues = []string{"required", "preferred", "discouraged"}

// IsUserVerification reports whether v is an accepted policy.
func IsUserVerification(v string) bool {
	for _, u := range UserVerificationValues {
		if u == v {
			return true
		}
	}
	return false
}

// Service resolves endpoints account-scoped and demo-aware. Demo may be nil
// (no demo endpoints configured).
type Service struct {
	Endpoints *store.Endpoints
	Demo      *demo.Service

	// Sessions reports active (not ended) terminal sessions, guest sessions
	// included (terminal.Manager). nil skips that part of the delete guard
	// (tests).
	Sessions ActiveSessions
	// LiveGuest reports a live guest session for the endpoint, including one
	// with no terminal session right now (waiting to attach, or refused and
	// allowed to ask again): it may still dial the endpoint, so it blocks a
	// delete like an open session. nil-able.
	LiveGuest func(accountID, endpointID string) bool
	// OnDeleted runs after a delete, so the endpoint's outstanding tickets
	// end with it (#306). nil-able.
	OnDeleted func(accountID, endpointID string)
}

// ActiveSessions is satisfied by terminal.Manager.
type ActiveSessions interface {
	HasActiveSession(accountID, endpointID string) bool
}

var (
	// ErrDemoReadOnly: demo endpoints cannot be changed.
	ErrDemoReadOnly = errors.New("Demo endpoints are read-only")
	// ErrActiveSessions: the endpoint has active sessions (any source).
	ErrActiveSessions = errors.New("Cannot delete endpoint with active sessions")
)

// Delete removes an account-scoped endpoint for REST and MCP alike. It is
// refused while the endpoint has active sessions (UI, MCP or guest, or a guest
// that may still connect); ended sessions never block it. On success the
// post-delete hook revokes the endpoint's outstanding tickets. Returns false
// when nothing matched.
func (s *Service) Delete(ctx context.Context, id, accountID string) (bool, error) {
	if demo.IsID(id) {
		return false, ErrDemoReadOnly
	}
	if s.hasActiveSessions(accountID, id) {
		slog.Info("endpoint: delete refused", "account", accountID, "endpoint", id, "reason", "active sessions")
		return false, ErrActiveSessions
	}
	ok, err := s.Endpoints.Delete(ctx, id, accountID)
	if err != nil || !ok {
		return ok, err
	}
	slog.Info("endpoint: deleted", "account", accountID, "endpoint", id)
	if s.OnDeleted != nil {
		s.OnDeleted(accountID, id)
	}
	return true, nil
}

func (s *Service) hasActiveSessions(accountID, endpointID string) bool {
	return (s.Sessions != nil && s.Sessions.HasActiveSession(accountID, endpointID)) ||
		(s.LiveGuest != nil && s.LiveGuest(accountID, endpointID))
}

// Endpoint is a resolved endpoint plus its provenance.
type Endpoint struct {
	store.Endpoint
	IsDemo bool
}

// ListForAccount returns the account's own endpoints, then the demo entries
// when the account's visibility toggle shows them (order pinned by the
// endpoints-list golden). A toggle read error degrades to "hidden".
func (s *Service) ListForAccount(ctx context.Context, accountID string) ([]Endpoint, error) {
	own, err := s.Endpoints.ListForAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]Endpoint, 0, len(own))
	for _, e := range own {
		out = append(out, Endpoint{Endpoint: e})
	}
	if show, _ := s.Endpoints.ShowDemoEndpoints(ctx, accountID); show && s.Demo != nil {
		for _, e := range s.Demo.List(accountID) {
			out = append(out, Endpoint{Endpoint: e, IsDemo: true})
		}
	}
	return out, nil
}

// GetForAccount resolves one endpoint scoped to the account; nil when the id
// doesn't resolve (unknown and foreign ids are indistinguishable — no
// cross-account probing). Demo ids resolve regardless of the visibility
// toggle, so a caller that already knows the id can still inspect it.
func (s *Service) GetForAccount(ctx context.Context, id, accountID string) (*Endpoint, error) {
	if demo.IsID(id) {
		if s.Demo != nil {
			for _, e := range s.Demo.List(accountID) {
				if e.ID == id {
					return &Endpoint{Endpoint: e, IsDemo: true}, nil
				}
			}
		}
		return nil, nil
	}
	ep, err := s.Endpoints.GetForAccount(ctx, id, accountID)
	if err != nil || ep == nil {
		return nil, err
	}
	return &Endpoint{Endpoint: *ep}, nil
}

// RefForAccount resolves an endpoint into the terminal.EndpointRef that
// session creation consumes; nil when the id doesn't resolve for the account.
func (s *Service) RefForAccount(ctx context.Context, id, accountID string) (*terminal.EndpointRef, error) {
	ep, err := s.GetForAccount(ctx, id, accountID)
	if err != nil || ep == nil {
		return nil, err
	}
	ref := terminal.EndpointRef{
		ID: ep.ID, Label: ep.Label, AccountID: ep.AccountID, Host: ep.Host, Port: int(ep.Port),
		Username: ep.Username, UserVerification: ep.UserVerification, AgentForward: ep.AgentForward,
	}
	return &ref, nil
}

// ActiveRefForAccount is RefForAccount restricted to endpoints that are not
// soft-deleted — what one-time access tickets resolve (#306): a ticket must
// not reach an endpoint its owner deleted. Demo endpoints are always active.
func (s *Service) ActiveRefForAccount(ctx context.Context, id, accountID string) (*terminal.EndpointRef, error) {
	if !demo.IsID(id) {
		active, err := s.Endpoints.IsActive(ctx, id, accountID)
		if err != nil || !active {
			return nil, err
		}
	}
	return s.RefForAccount(ctx, id, accountID)
}
