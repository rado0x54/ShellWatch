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
	"errors"
	"fmt"
	"time"

	"github.com/rado0x54/shellwatch/internal/endpointsvc"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
	"github.com/rado0x54/shellwatch/internal/util"
)

// Deps are the collaborators an AgentSession needs.
type Deps struct {
	Manager *terminal.Manager
	Svc     *endpointsvc.Service
}

// Session scopes one request's terminal-session access to an OAuth client on
// an account. It is cheap to build and not safe for concurrent use — make one
// per request.
type Session struct {
	deps      Deps
	accountID string
	clientID  string
	sourceIP  string

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
}

// New builds an AgentSession for one request.
func New(p Params) *Session {
	return &Session{deps: p.Deps, accountID: p.AccountID, clientID: p.ClientID, sourceIP: p.SourceIP}
}

// SetClientInfo records the MCP client's advertised name/version (sanitized).
func (s *Session) SetClientInfo(name, version string) {
	s.clientName = util.SanitizeClientReported(name)
	s.clientVer = util.SanitizeClientReported(version)
}

// AccountID is the account this request acts for.
func (s *Session) AccountID() string { return s.accountID }

// ClientID is the authenticated OAuth client_id ownership is scoped to.
func (s *Session) ClientID() string { return s.clientID }

// SourceIP is the request's effective client IP.
func (s *Session) SourceIP() string { return s.sourceIP }

// ClientInfo returns the (sanitized) client-reported name and version.
func (s *Session) ClientInfo() (name, version string) { return s.clientName, s.clientVer }

// AssertOwned returns the uniform "session not found" error unless sessionID
// is one of this client's sessions.
func (s *Session) AssertOwned(sessionID string) error { return s.assertOwned(sessionID) }

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
func (s *Session) CreateEndpoint(ctx context.Context, id string, p endpointsvc.EndpointPatch) error {
	return s.deps.Svc.Create(ctx, endpointsvc.CreateParams{ID: id, AccountID: s.accountID, Patch: p})
}

// UpdateEndpoint patches an account-scoped endpoint. Returns false when no
// endpoint matched.
func (s *Session) UpdateEndpoint(ctx context.Context, id string, p endpointsvc.EndpointPatch) (bool, error) {
	return s.deps.Svc.Update(ctx, endpointsvc.UpdateParams{ID: id, AccountID: s.accountID, Patch: p, By: endpointsvc.Actor{
		Via: "MCP", MCPClientName: s.clientName, MCPClientVersion: s.clientVer, SourceIP: s.sourceIP,
	}})
}

// DeleteEndpoint removes an account-scoped endpoint. Returns false when nothing
// matched.
func (s *Session) DeleteEndpoint(ctx context.Context, id string) (bool, error) {
	return s.deps.Svc.Delete(ctx, id, s.accountID)
}

// CreateSession opens a session against an endpoint owned by the account,
// under the account-wide max_sessions. A foreign/unknown id always returns
// "unknown endpoint" (no cross-account probing / spurious approval prompts).
func (s *Session) CreateSession(ctx context.Context, endpointID, reason string) (*terminal.Session, error) {
	sess, err := s.deps.Svc.Open(ctx, s.accountID, endpointID, terminal.Trigger{
		Kind: terminal.SourceMCP, Reason: reason, SourceIP: s.sourceIP,
		OwnerClientID: s.clientID,
		MCPClientName: s.clientName, MCPClientVer: s.clientVer,
	})
	if errors.Is(err, endpointsvc.ErrEndpointNotFound) {
		return nil, fmt.Errorf("unknown endpoint: %s", endpointID)
	}
	return sess, err
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
