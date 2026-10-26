// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package agent is per-agent session isolation: an AgentSession scopes the
// terminal sessions an agent may touch to the OAuth client (and account) its
// bearer token was issued to. Since MCP 2026-07-28 there is no protocol-level
// connection to anchor ownership to (#243): an AgentSession is built per
// request from the request's principal, and ownership lives on the terminal
// session itself (terminal.Session.OwnerClientID). Endpoint listing/lookup is
// account-scoped.
package agent

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/rado0x54/shellwatch/internal/audit"
	"github.com/rado0x54/shellwatch/internal/endpointsvc"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
	"github.com/rado0x54/shellwatch/internal/util"
)

// HostKeyAuditor records host-key audit events (satisfied by *audit.Writer;
// nil skips auditing — tests).
type HostKeyAuditor interface {
	RecordHostKeyEvent(ev audit.HostKeyEvent) string
}

// Deps are the collaborators an AgentSession needs.
type Deps struct {
	Manager *terminal.Manager
	Svc     *endpointsvc.Service
	// Audit records the host-key-cleared event when an MCP endpoint update
	// changes host/port (#241); may be nil.
	Audit HostKeyAuditor
}

// Session scopes one request's terminal-session access to an OAuth client on
// an account. It is cheap to build and not safe for concurrent use — make one
// per request.
type Session struct {
	deps      Deps
	accountID string
	clientID  string
	sourceIP  string
	maxOwned  int

	clientName string
	clientVer  string
}

// Params configures New.
type Params struct {
	Deps      Deps
	AccountID string
	// ClientID is the OAuth client_id ownership is scoped to (introspection
	// client_id). Sessions created here carry it; only sessions carrying it
	// are visible.
	ClientID string
	SourceIP string
	// MaxOwned caps this client's concurrent live sessions: negative means
	// "unresolved, use the default 5"; an explicit 0 blocks all creation
	// (a stored max_sessions of 0 must not silently upgrade to 5).
	MaxOwned int
}

// New builds an AgentSession for one request.
func New(p Params) *Session {
	if p.MaxOwned < 0 {
		p.MaxOwned = 5
	}
	return &Session{deps: p.Deps, accountID: p.AccountID, clientID: p.ClientID, sourceIP: p.SourceIP, maxOwned: p.MaxOwned}
}

// SetClientInfo records the MCP client's advertised name/version (sanitized).
func (s *Session) SetClientInfo(name, version string) {
	s.clientName = util.SanitizeClientReported(name)
	s.clientVer = util.SanitizeClientReported(version)
}

// EndpointInfo is the subset the MCP list tool returns (contract item C: MCP
// list omits userVerification/agentForward/isDemo).
type EndpointInfo struct {
	ID          string
	Label       string
	Host        string
	Port        int64
	Username    string
	Description *string
}

// ListEndpoints returns the account's endpoints (+ demo when visible).
func (s *Session) ListEndpoints(ctx context.Context) ([]EndpointInfo, error) {
	merged, err := s.deps.Svc.ListForAccount(ctx, s.accountID)
	if err != nil {
		return nil, err
	}
	out := make([]EndpointInfo, 0, len(merged))
	for _, e := range merged {
		out = append(out, EndpointInfo{ID: e.ID, Label: e.Label, Host: e.Host, Port: e.Port, Username: e.Username, Description: e.Description})
	}
	return out, nil
}

// GetEndpoint returns a full endpoint scoped to the account (nil when absent).
func (s *Session) GetEndpoint(ctx context.Context, id string) (*store.Endpoint, error) {
	ep, err := s.deps.Svc.GetForAccount(ctx, id, s.accountID)
	if err != nil || ep == nil {
		return nil, err
	}
	return &ep.Endpoint, nil
}

// CreateEndpoint creates an account-scoped endpoint (MCP path — the caller
// supplies the id, unlike REST which mints one).
func (s *Session) CreateEndpoint(ctx context.Context, ep store.Endpoint) error {
	ep.AccountID = s.accountID
	return s.deps.Svc.Endpoints.Create(ctx, ep)
}

// EndpointPatch is a typed partial endpoint update; nil fields keep the
// stored value. Description carries an explicit set flag so a JSON null can
// clear it.
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

// UpdateEndpoint read-merges a typed patch into an account-scoped endpoint and
// writes it back. Returns false when no endpoint matched. Wire-shape decoding
// and field validation (userVerification enum, description cap) happen at the
// caller (internal/mcp).
func (s *Session) UpdateEndpoint(ctx context.Context, id string, patch EndpointPatch) (bool, error) {
	existing, err := s.deps.Svc.Endpoints.GetForAccount(ctx, id, s.accountID)
	if err != nil || existing == nil {
		return false, err
	}
	merged := *existing
	if patch.Label != nil {
		merged.Label = *patch.Label
	}
	if patch.Host != nil {
		merged.Host = *patch.Host
	}
	if patch.Port != nil {
		merged.Port = *patch.Port
	}
	if patch.Username != nil {
		merged.Username = *patch.Username
	}
	if patch.UserVerification != nil {
		merged.UserVerification = *patch.UserVerification
	}
	if patch.AgentForward != nil {
		merged.AgentForward = *patch.AgentForward
	}
	if patch.DescriptionSet {
		merged.Description = patch.Description
	}
	ok, err := s.deps.Svc.Endpoints.Update(ctx, merged)
	// The store cleared the pinned host key atomically when host/port changed
	// (#241): the agent cannot carry a pin over to a new address. Audit it —
	// this is the only way MCP can touch a pin, and it must leave a trace.
	if ok && err == nil && s.deps.Audit != nil && existing.HostKey != nil &&
		(existing.Host != merged.Host || existing.Port != merged.Port) {
		s.deps.Audit.RecordHostKeyEvent(audit.HostKeyEvent{
			Type: "host-key-cleared", Source: "endpoint-admin",
			AccountID: existing.AccountID, EndpointID: existing.ID, EndpointLabel: existing.Label,
			EndpointAddress:  existing.Username + "@" + existing.Host + ":" + strconv.FormatInt(existing.Port, 10),
			Fingerprint:      existing.HostKey.Fingerprint,
			Reason:           "endpoint host/port updated via MCP",
			MCPClientName:    s.clientName,
			MCPClientVersion: s.clientVer,
			SourceIP:         s.sourceIP,
		})
	}
	return ok, err
}

// DeleteEndpoint removes an account-scoped endpoint. Returns false when nothing
// matched.
func (s *Session) DeleteEndpoint(ctx context.Context, id string) (bool, error) {
	return s.deps.Svc.Endpoints.Delete(ctx, id, s.accountID)
}

// CreateSession opens a session against an endpoint owned by the account. A
// foreign/unknown id always returns "Unknown endpoint" (no cross-account
// probing / spurious approval prompts).
func (s *Session) CreateSession(ctx context.Context, endpointID, reason string) (*terminal.Session, error) {
	ep, err := s.deps.Svc.RefForAccount(ctx, endpointID, s.accountID)
	if err != nil {
		return nil, err
	}
	if ep == nil {
		return nil, fmt.Errorf("unknown endpoint: %s", endpointID)
	}
	// The cap counts only LIVE sessions owned by this client: dead-but-retained
	// (post-mortem closed/error) sessions stay readable via read_output but do
	// not starve the cap.
	live := 0
	for _, sess := range s.deps.Manager.ListSessions() {
		if s.ownsSession(&sess) && sess.Status != terminal.StatusClosed && sess.Status != terminal.StatusError {
			live++
		}
	}
	if live >= s.maxOwned {
		return nil, fmt.Errorf("maximum concurrent sessions (%d) reached", s.maxOwned)
	}

	return s.deps.Manager.Create(ctx, *ep, s.accountID, terminal.Trigger{
		Kind: terminal.SourceMCP, Reason: reason, SourceIP: s.sourceIP,
		OwnerClientID: s.clientID,
		MCPClientName: s.clientName, MCPClientVer: s.clientVer,
	})
}

// ListSessions returns this client's owned sessions (live and retained
// post-mortem ones, until the manager forgets them).
func (s *Session) ListSessions() []terminal.Session {
	var out []terminal.Session
	for _, sess := range s.deps.Manager.ListSessions() {
		if s.ownsSession(&sess) {
			out = append(out, sess)
		}
	}
	return out
}

// SendKeys resolves and sends keys to an owned session.
func (s *Session) SendKeys(sessionID string, keys []string) error {
	if err := s.assertOwned(sessionID); err != nil {
		return err
	}
	data, err := terminal.ResolveKeys(keys)
	if err != nil {
		return err
	}
	return s.deps.Manager.SendInput(sessionID, data)
}

// ReadOutputParams configures ReadOutput.
type ReadOutputParams struct {
	SessionID   string
	AfterOffset int64
	Limit       int
	// Wait long-polls: when no output past AfterOffset exists yet, block until
	// some arrives, the session reaches a terminal state, or Wait elapses —
	// then read once more and return. 0 reads immediately (#243, the
	// era-independent replacement for the removed output_available
	// notification).
	Wait time.Duration
}

// ReadOutput reads owned-session output, optionally long-polling.
func (s *Session) ReadOutput(ctx context.Context, p ReadOutputParams) (terminal.ReadResult, error) {
	if err := s.assertOwned(p.SessionID); err != nil {
		return terminal.ReadResult{}, err
	}
	res, err := s.deps.Manager.ReadOutput(p.SessionID, p.AfterOffset, p.Limit)
	if err != nil || p.Wait <= 0 || len(res.Data) > 0 {
		return res, err
	}
	if sess := s.deps.Manager.GetSession(p.SessionID); sess == nil ||
		sess.Status == terminal.StatusClosed || sess.Status == terminal.StatusError {
		return res, err
	}

	wake := make(chan struct{}, 1)
	poke := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	unsubOut := s.deps.Manager.SubscribeOutput(func(id string, _ int64) {
		if id == p.SessionID {
			poke()
		}
	})
	defer unsubOut()
	unsubStatus := s.deps.Manager.SubscribeStatus(func(ev terminal.StatusEvent) {
		if ev.SessionID == p.SessionID &&
			(ev.Status == terminal.StatusClosed || ev.Status == terminal.StatusError) {
			poke()
		}
	})
	defer unsubStatus()

	timer := time.NewTimer(p.Wait)
	defer timer.Stop()
	for {
		// Re-read first: output or a terminal state may have landed between the
		// initial read and the subscriptions above.
		res, err = s.deps.Manager.ReadOutput(p.SessionID, p.AfterOffset, p.Limit)
		if err != nil || len(res.Data) > 0 {
			return res, err
		}
		if sess := s.deps.Manager.GetSession(p.SessionID); sess == nil ||
			sess.Status == terminal.StatusClosed || sess.Status == terminal.StatusError {
			return res, err
		}
		select {
		case <-wake:
		case <-timer.C:
			return s.deps.Manager.ReadOutput(p.SessionID, p.AfterOffset, p.Limit)
		case <-ctx.Done():
			return res, ctx.Err()
		}
	}
}

// CloseSession closes an owned session.
func (s *Session) CloseSession(sessionID string) error {
	if err := s.assertOwned(sessionID); err != nil {
		return err
	}
	s.deps.Manager.Close(sessionID, terminal.CloseClientMCP)
	return nil
}

// Owns reports whether sessionID is one of this client's sessions (the MCP
// resource watcher filters the manager's fan-out with it).
func (s *Session) Owns(sessionID string) bool {
	return s.ownsSession(s.deps.Manager.GetSession(sessionID))
}

func (s *Session) ownsSession(sess *terminal.Session) bool {
	return sess != nil && sess.Source == terminal.SourceMCP &&
		sess.AccountID == s.accountID && sess.OwnerClientID == s.clientID
}

func (s *Session) assertOwned(sessionID string) error {
	if !s.Owns(sessionID) {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	return nil
}
