// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package endpointsvc is the one endpoint service for REST, MCP and the
// ticket service (#326): reads (demo-aware), create/update (defaults,
// validation, merge, host-key audit), delete (active-session guard) and
// opening a session (lookup, max_sessions, Manager.Create). The wire layers
// only decode and map errors. Demo entries are synthesized per request,
// never stored, and are read-only.
package endpointsvc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/rado0x54/shellwatch/internal/audit"
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

// DefaultMaxSessions applies when an account's max_sessions can't be read.
const DefaultMaxSessions = 20

// Service is the endpoint service. Demo may be nil (no demo endpoints
// configured); every other nil-able field is noted.
type Service struct {
	Endpoints *store.Endpoints
	Demo      *demo.Service

	// Sessions is terminal.Manager: the delete guard and Open. nil skips the
	// guard (tests); Open needs it.
	Sessions SessionManager
	// MaxSessions resolves an account's max_sessions; nil or a miss applies
	// DefaultMaxSessions.
	MaxSessions func(ctx context.Context, accountID string) (int, bool)
	// Audit records host-key-cleared events (*audit.Writer). nil-able.
	Audit HostKeyAuditor
	// LiveGuest reports a live guest session for the endpoint, including one
	// with no terminal session right now (waiting to attach, or refused and
	// allowed to ask again): it may still dial the endpoint, so it blocks a
	// delete like an open session. nil-able.
	LiveGuest func(accountID, endpointID string) bool
	// OnDeleted runs after a delete, so the endpoint's outstanding tickets
	// end with it (#306). nil-able.
	OnDeleted func(accountID, endpointID string)
	// OnTargetChanged runs after an update changed host, port or username:
	// unredeemed tickets were minted for the old target. nil-able.
	OnTargetChanged func(accountID, endpointID string)
}

// SessionManager is satisfied by terminal.Manager.
type SessionManager interface {
	HasActiveSession(accountID, endpointID string) bool
	Create(ctx context.Context, ep terminal.EndpointRef, expectedAccountID string, trigger terminal.Trigger) (*terminal.Session, error)
}

// HostKeyAuditor records host-key audit events (satisfied by *audit.Writer).
type HostKeyAuditor interface {
	RecordHostKeyEvent(ev audit.HostKeyEvent) string
}

var (
	// ErrDemoReadOnly: demo endpoints cannot be changed.
	ErrDemoReadOnly = errors.New("Demo endpoints are read-only")
	// ErrActiveSessions: the endpoint has active sessions (any source).
	ErrActiveSessions = errors.New("Cannot delete endpoint with active sessions")
	// ErrLabelHostRequired: create without a label or host.
	ErrLabelHostRequired = errors.New("label and host are required")
	// ErrEndpointNotFound: Open on an id that doesn't resolve for the account.
	ErrEndpointNotFound = errors.New("Endpoint not found")
	// ErrTargetChanged: Open for a ticket whose endpoint now points at a
	// different host, port or username than the ticket was minted for.
	ErrTargetChanged = errors.New("endpoint target changed since the ticket was minted")
	// ErrEndpointLookup: Open could not read the endpoint (wrapped cause).
	ErrEndpointLookup = errors.New("endpoint lookup failed")
)

// FieldError is a patch field outside its constraints; Msg names the field
// without a wire prefix (REST writes it as is, MCP prefixes "data.").
type FieldError struct{ Msg string }

func (e *FieldError) Error() string { return e.Msg }

// EndpointPatch is a typed partial endpoint; nil fields keep the stored value
// (update) or take the default (create). Description carries an explicit set
// flag so a JSON null can clear it.
type EndpointPatch struct {
	Label            *string
	Host             *string
	Port             *int64
	Username         *string
	UserVerification *string
	AgentForward     *bool
	Description      *string // applied only when DescriptionSet; nil clears
	DescriptionSet   bool
}

func (p EndpointPatch) validate() error {
	if p.UserVerification != nil && !IsUserVerification(*p.UserVerification) {
		return &FieldError{"userVerification must be one of: " + strings.Join(UserVerificationValues, ", ")}
	}
	if p.Description != nil && len(*p.Description) > DescriptionMaxLen {
		return &FieldError{"description must be a string up to 1000 characters"}
	}
	return nil
}

// apply merges the patch into ep. Descriptions are trimmed; blank clears.
func (p EndpointPatch) apply(ep *store.Endpoint) {
	set := func(dst *string, v *string) {
		if v != nil {
			*dst = *v
		}
	}
	set(&ep.Label, p.Label)
	set(&ep.Host, p.Host)
	set(&ep.Username, p.Username)
	set(&ep.UserVerification, p.UserVerification)
	if p.Port != nil {
		ep.Port = *p.Port
	}
	if p.AgentForward != nil {
		ep.AgentForward = *p.AgentForward
	}
	if p.DescriptionSet {
		ep.Description = nil
		if p.Description != nil {
			if d := strings.TrimSpace(*p.Description); d != "" {
				ep.Description = &d
			}
		}
	}
}

// CreateParams configures Create. The id is the wire layer's (REST mints
// one, MCP takes the caller's).
type CreateParams struct {
	ID, AccountID string
	Patch         EndpointPatch
}

// Create stores a new endpoint. Defaults: port 22, username "shellwatch",
// userVerification "required", agentForward true. Label and host are
// trimmed and required.
func (s *Service) Create(ctx context.Context, p CreateParams) error {
	if demo.IsID(p.ID) {
		return ErrDemoReadOnly
	}
	if err := p.Patch.validate(); err != nil {
		return err
	}
	ep := store.Endpoint{
		ID: p.ID, AccountID: p.AccountID, Port: 22, Username: "shellwatch",
		UserVerification: "required", AgentForward: true,
	}
	p.Patch.DescriptionSet = true
	p.Patch.apply(&ep)
	ep.Label, ep.Host = strings.TrimSpace(ep.Label), strings.TrimSpace(ep.Host)
	if ep.Label == "" || ep.Host == "" {
		return ErrLabelHostRequired
	}
	if err := s.Endpoints.Create(ctx, ep); err != nil {
		return err
	}
	slog.Info("endpoint: created", "account", p.AccountID, "endpoint", p.ID)
	return nil
}

// Actor names who changed an endpoint, for the host-key audit.
type Actor struct {
	Via                             string // "REST" or "MCP"
	MCPClientName, MCPClientVersion string
	SourceIP                        string
}

// UpdateParams configures Update.
type UpdateParams struct {
	ID, AccountID string
	Patch         EndpointPatch
	By            Actor
}

// Update read-merges a patch into a stored endpoint. Running sessions keep
// the copy they connected with. A host or port change clears the pinned host
// key (in the store) and audits it. Tickets are bound to the target they were
// minted for (checked at redeem and at connect), so a host, port or username
// change ends their use either way; OnTargetChanged only clears the
// unredeemed ones from the owner's list right away. Returns false when
// nothing matched.
func (s *Service) Update(ctx context.Context, p UpdateParams) (bool, error) {
	if demo.IsID(p.ID) {
		return false, ErrDemoReadOnly
	}
	if err := p.Patch.validate(); err != nil {
		return false, err
	}
	old, err := s.Endpoints.GetForAccount(ctx, p.ID, p.AccountID)
	if err != nil || old == nil {
		return false, err
	}
	merged := *old
	p.Patch.apply(&merged)
	if ok, err := s.Endpoints.Update(ctx, merged); err != nil || !ok {
		return ok, err
	}
	slog.Info("endpoint: updated", "account", p.AccountID, "endpoint", p.ID)
	if old.Host != merged.Host || old.Port != merged.Port {
		s.AuditHostKeyCleared(*old, "endpoint host/port updated via "+p.By.Via, p.By)
	}
	if (old.Host != merged.Host || old.Port != merged.Port || old.Username != merged.Username) && s.OnTargetChanged != nil {
		s.OnTargetChanged(p.AccountID, p.ID)
	}
	return true, nil
}

// AuditHostKeyCleared records that ep's pinned host key (if any) was cleared.
func (s *Service) AuditHostKeyCleared(ep store.Endpoint, reason string, by Actor) {
	if s.Audit == nil || ep.HostKey == nil {
		return
	}
	s.Audit.RecordHostKeyEvent(audit.HostKeyEvent{
		Type: "host-key-cleared", Source: "endpoint-admin",
		AccountID: ep.AccountID, EndpointID: ep.ID, EndpointLabel: ep.Label,
		EndpointAddress: ep.Username + "@" + ep.Host + ":" + strconv.FormatInt(ep.Port, 10),
		Fingerprint:     ep.HostKey.Fingerprint, Reason: reason,
		MCPClientName: by.MCPClientName, MCPClientVersion: by.MCPClientVersion, SourceIP: by.SourceIP,
	})
}

// Open is the one way to open a session (UI, MCP, guest): resolve the
// endpoint, apply max_sessions — every opening or open session of the
// account, any source — and connect. Errors: ErrEndpointNotFound,
// ErrEndpointLookup, ErrTargetChanged, *terminal.LimitError, or the connect
// error. A guest connects only to the target its ticket was minted for, and
// its agent forwarding never goes beyond the endpoint's own setting.
func (s *Service) Open(ctx context.Context, accountID, endpointID string, trigger terminal.Trigger) (*terminal.Session, error) {
	ref, err := s.RefForAccount(ctx, endpointID, accountID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEndpointLookup, err)
	}
	if ref == nil {
		return nil, ErrEndpointNotFound
	}
	if trigger.Ticket != nil {
		if trigger.Ticket.Target != ref.Target() {
			slog.Info("terminal: session refused", "account", accountID, "endpoint", endpointID,
				"source", trigger.Kind, "reason", "endpoint target changed since the ticket was minted")
			return nil, ErrTargetChanged
		}
		ref.AgentForward = ref.AgentForward && trigger.Ticket.AgentForward
	}
	max := DefaultMaxSessions
	if s.MaxSessions != nil {
		if m, ok := s.MaxSessions(ctx, accountID); ok {
			max = m
		}
	}
	trigger.MaxActive = max
	var sess *terminal.Session
	if max <= 0 { // a stored 0 blocks every open; it never means "unlimited"
		err = &terminal.LimitError{Max: max}
	} else {
		sess, err = s.Sessions.Create(ctx, *ref, accountID, trigger)
	}
	if limit := (*terminal.LimitError)(nil); errors.As(err, &limit) {
		slog.Info("terminal: session refused", "account", accountID, "endpoint", endpointID,
			"source", trigger.Kind, "reason", "session limit reached", "max", max)
	}
	return sess, err
}

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
