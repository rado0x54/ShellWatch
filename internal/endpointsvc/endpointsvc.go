// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package endpointsvc is the shared endpoint read/resolution layer for REST,
// the agent session (MCP), and session creation. It owns the demo-endpoint
// merge rules and the field constraints both wire layers enforce — before it
// existed, the demo-aware resolution was hand-rolled three times and the
// validation constants twice, and the copies had already drifted once.
// Mutations (create/update/delete) go straight to Endpoints: demo entries are
// synthesized per request, never stored, and the wire layers reject demo ids
// before mutating.
package endpointsvc

import (
	"context"

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
