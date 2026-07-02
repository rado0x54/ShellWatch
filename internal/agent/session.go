// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package agent is per-agent session isolation (port of src/agent/): an
// AgentSession owns the terminal sessions created by one agent connection
// (MCP today, SSH server later) so each agent only sees its own sessions.
// Endpoint listing/lookup is account-scoped; on disconnect all owned sessions
// close.
package agent

import (
	"context"
	"fmt"
	"sync"

	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
	"github.com/rado0x54/shellwatch/internal/util"
)

// Deps are the collaborators an AgentSession needs.
type Deps struct {
	Manager   *terminal.Manager
	Endpoints *store.Endpoints
	Demo      *demo.Service
}

// Session isolates one agent connection's terminal sessions.
type Session struct {
	deps      Deps
	accountID string
	sourceIP  string
	maxOwned  int

	mu    sync.Mutex
	owned map[string]bool

	clientName string
	clientVer  string
}

// New builds an AgentSession for an account. maxOwned caps concurrent owned
// sessions (default 5).
func New(deps Deps, accountID, sourceIP string, maxOwned int) *Session {
	if maxOwned <= 0 {
		maxOwned = 5
	}
	return &Session{deps: deps, accountID: accountID, sourceIP: sourceIP, maxOwned: maxOwned, owned: map[string]bool{}}
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
	own, err := s.deps.Endpoints.ListForAccount(ctx, s.accountID)
	if err != nil {
		return nil, err
	}
	merged := own
	if show, _ := s.deps.Endpoints.ShowDemoEndpoints(ctx, s.accountID); show && s.deps.Demo != nil {
		merged = append(merged, s.deps.Demo.List(s.accountID)...)
	}
	out := make([]EndpointInfo, 0, len(merged))
	for _, e := range merged {
		out = append(out, EndpointInfo{ID: e.ID, Label: e.Label, Host: e.Host, Port: e.Port, Username: e.Username, Description: e.Description})
	}
	return out, nil
}

// GetEndpoint returns a full endpoint scoped to the account (nil when absent).
func (s *Session) GetEndpoint(ctx context.Context, id string) (*store.Endpoint, error) {
	if demo.IsID(id) && s.deps.Demo != nil {
		for _, e := range s.deps.Demo.List(s.accountID) {
			if e.ID == id {
				e := e
				return &e, nil
			}
		}
		return nil, nil
	}
	return s.deps.Endpoints.GetForAccount(ctx, id, s.accountID)
}

// CreateSession opens a session against an endpoint owned by the account. A
// foreign/unknown id always returns "Unknown endpoint" (no cross-account
// probing / spurious approval prompts).
func (s *Session) CreateSession(ctx context.Context, endpointID, reason string) (*terminal.Session, error) {
	ep, err := s.resolveRef(ctx, endpointID)
	if err != nil {
		return nil, err
	}
	if ep == nil {
		return nil, fmt.Errorf("unknown endpoint: %s", endpointID)
	}
	s.mu.Lock()
	if len(s.owned) >= s.maxOwned {
		s.mu.Unlock()
		return nil, fmt.Errorf("maximum concurrent sessions (%d) reached", s.maxOwned)
	}
	s.mu.Unlock()

	sess, err := s.deps.Manager.Create(ctx, *ep, s.accountID, terminal.Trigger{
		Kind: terminal.SourceMCP, Reason: reason, SourceIP: s.sourceIP,
		MCPClientName: s.clientName, MCPClientVer: s.clientVer,
	})
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.owned[sess.SessionID] = true
	s.mu.Unlock()
	return sess, nil
}

func (s *Session) resolveRef(ctx context.Context, id string) (*terminal.EndpointRef, error) {
	ep, err := s.GetEndpoint(ctx, id)
	if err != nil || ep == nil {
		return nil, err
	}
	ref := terminal.EndpointRef{
		ID: ep.ID, AccountID: ep.AccountID, Host: ep.Host, Port: int(ep.Port),
		Username: ep.Username, UserVerification: ep.UserVerification, AgentForward: ep.AgentForward,
	}
	return &ref, nil
}

// ListSessions returns this agent's owned sessions.
func (s *Session) ListSessions() []terminal.Session {
	s.mu.Lock()
	owned := make(map[string]bool, len(s.owned))
	for k := range s.owned {
		owned[k] = true
	}
	s.mu.Unlock()
	var out []terminal.Session
	for _, sess := range s.deps.Manager.ListSessions() {
		if owned[sess.SessionID] {
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

// ReadOutput reads owned-session output.
func (s *Session) ReadOutput(sessionID string, afterOffset int64, limit int) (terminal.ReadResult, error) {
	if err := s.assertOwned(sessionID); err != nil {
		return terminal.ReadResult{}, err
	}
	return s.deps.Manager.ReadOutput(sessionID, afterOffset, limit)
}

// CloseSession closes an owned session.
func (s *Session) CloseSession(sessionID string) error {
	if err := s.assertOwned(sessionID); err != nil {
		return err
	}
	s.deps.Manager.Close(sessionID, terminal.CloseClientMCP)
	s.mu.Lock()
	delete(s.owned, sessionID)
	s.mu.Unlock()
	return nil
}

// Destroy closes all owned sessions (agent disconnect).
func (s *Session) Destroy() {
	s.mu.Lock()
	ids := make([]string, 0, len(s.owned))
	for id := range s.owned {
		ids = append(ids, id)
	}
	s.owned = map[string]bool{}
	s.mu.Unlock()
	for _, id := range ids {
		s.deps.Manager.Close(id, terminal.CloseAgentDisconnect)
	}
}

func (s *Session) assertOwned(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.owned[sessionID] {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	return nil
}
