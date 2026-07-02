// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Manager is the central session registry (port of terminal-manager.ts,
// docs/go-backend-architecture.md §5.2): source-agnostic, owns session
// lifecycle, one pump goroutine per session. Subscribers get guaranteed
// status hooks (audit) + coalesced output wake-ups (WS/MCP) — the coalesced
// side lands with the WS hub (slice 4); slice 2 provides the core + a
// status-event fan-out.
package terminal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
)

type managed struct {
	session   *Session
	transport Transport
	output    *OutputBuffer
}

// StatusEvent is emitted on every status transition (guaranteed, ordered).
type StatusEvent struct {
	SessionID string
	Status    Status
	Previous  Status
	Reason    CloseReason
}

// Manager owns all sessions.
type Manager struct {
	mu            sync.Mutex
	terminals     map[string]*managed
	factory       TransportFactory
	clk           clock.Clock
	maxBufferSize int

	statusSubs map[int]func(StatusEvent)
	outputSubs map[int]func(sessionID string, offset int64)
	nextSub    int
}

// NewManager builds a Manager. factory establishes transports.
func NewManager(factory TransportFactory, clk clock.Clock, maxBufferSize int) *Manager {
	if clk == nil {
		clk = clock.Real{}
	}
	return &Manager{
		terminals: map[string]*managed{}, factory: factory, clk: clk,
		maxBufferSize: maxBufferSize,
		statusSubs:    map[int]func(StatusEvent){},
		outputSubs:    map[int]func(string, int64){},
	}
}

// SubscribeStatus registers a guaranteed status hook; returns an unsubscribe.
func (m *Manager) SubscribeStatus(fn func(StatusEvent)) func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextSub
	m.nextSub++
	m.statusSubs[id] = fn
	return func() { m.mu.Lock(); delete(m.statusSubs, id); m.mu.Unlock() }
}

// SubscribeOutput registers an output notifier (sessionID, currentOffset).
func (m *Manager) SubscribeOutput(fn func(sessionID string, offset int64)) func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextSub
	m.nextSub++
	m.outputSubs[id] = fn
	return func() { m.mu.Lock(); delete(m.outputSubs, id); m.mu.Unlock() }
}

// Create opens a session against an endpoint. expectedAccountID guards
// cross-account creation (terminal-manager.ts:62, #130).
func (m *Manager) Create(ctx context.Context, ep EndpointRef, expectedAccountID string, trigger Trigger) (*Session, error) {
	if ep.AccountID != expectedAccountID {
		return nil, fmt.Errorf("unknown endpoint: %s", ep.ID)
	}
	now := m.clk.Now()
	sess := &Session{
		SessionID: GenerateSessionID(), EndpointID: ep.ID, AccountID: ep.AccountID,
		Status: StatusOpening, CreatedAt: now, LastActivityAt: now, Source: trigger.Kind,
		SourceIP: trigger.SourceIP,
	}
	if trigger.Kind == SourceMCP {
		sess.MCPReason = trigger.Reason
		sess.MCPClientName = trigger.MCPClientName
		sess.MCPClientVer = trigger.MCPClientVer
	}

	transport, err := m.factory(ctx, FactoryParams{Endpoint: ep, SessionID: sess.SessionID, Trigger: trigger})
	if err != nil {
		sess.Status = StatusError
		return nil, fmt.Errorf("failed to connect to %s: %w", ep.ID, err)
	}

	mg := &managed{session: sess, transport: transport, output: NewOutputBuffer(m.maxBufferSize)}
	m.mu.Lock()
	m.terminals[sess.SessionID] = mg
	m.mu.Unlock()

	go m.pump(mg)

	m.setStatus(mg, StatusOpen, "")
	out := *sess
	out.Status = StatusOpen
	return &out, nil
}

// pump ranges over transport events until it ends (one goroutine per session).
// An explicit Err/Closed event drives the terminal state; if the channel just
// closes (the client-initiated close path, where transport.Close suppresses a
// duplicate Closed event), the session is still finalized here — reasonOr
// preserves the reason Close() already stamped (e.g. client.ui).
func (m *Manager) pump(mg *managed) {
	for ev := range mg.transport.Events() {
		switch {
		case ev.Err != nil:
			m.setStatus(mg, StatusError, reasonOr(mg, CloseTransportError))
			return
		case ev.Closed:
			m.setStatus(mg, StatusClosed, reasonOr(mg, CloseServerHangup))
			return
		default:
			mg.output.Append(ev.Data)
			m.mu.Lock()
			mg.session.LastActivityAt = m.clk.Now()
			offset := mg.output.CurrentOffset()
			subs := make([]func(string, int64), 0, len(m.outputSubs))
			for _, fn := range m.outputSubs {
				subs = append(subs, fn)
			}
			m.mu.Unlock()
			for _, fn := range subs {
				fn(mg.session.SessionID, offset)
			}
		}
	}
	m.setStatus(mg, StatusClosed, reasonOr(mg, CloseServerHangup))
}

func reasonOr(mg *managed, fallback CloseReason) CloseReason {
	if mg.session.CloseReason != "" {
		return mg.session.CloseReason
	}
	return fallback
}

// SendInput writes raw input to an open session.
func (m *Manager) SendInput(sessionID, input string) error {
	mg, err := m.get(sessionID)
	if err != nil {
		return err
	}
	if mg.session.Status != StatusOpen {
		return fmt.Errorf("terminal %s is not open (status: %s)", sessionID, mg.session.Status)
	}
	return mg.transport.Write([]byte(input))
}

// SendKeys resolves named keys and writes them.
func (m *Manager) SendKeys(sessionID string, keys []string) error {
	resolved, err := ResolveKeys(keys)
	if err != nil {
		return err
	}
	return m.SendInput(sessionID, resolved)
}

// ReadOutput reads up to limit bytes after afterOffset.
func (m *Manager) ReadOutput(sessionID string, afterOffset int64, limit int) (ReadResult, error) {
	mg, err := m.get(sessionID)
	if err != nil {
		return ReadResult{}, err
	}
	return mg.output.Read(afterOffset, limit), nil
}

// ReadOutputFrom returns the tail from afterOffset with a reset flag.
func (m *Manager) ReadOutputFrom(sessionID string, afterOffset *int64) (FromResult, error) {
	mg, err := m.get(sessionID)
	if err != nil {
		return FromResult{}, err
	}
	return mg.output.ReadFrom(afterOffset), nil
}

// ReadOutputTail returns up to limit trailing bytes.
func (m *Manager) ReadOutputTail(sessionID string, limit int) []byte {
	mg, err := m.get(sessionID)
	if err != nil {
		return nil
	}
	return mg.output.Tail(limit)
}

// Resize changes the PTY size of an open session.
func (m *Manager) Resize(sessionID string, cols, rows int) error {
	mg, err := m.get(sessionID)
	if err != nil {
		return err
	}
	return mg.transport.Resize(cols, rows)
}

// ListSessions returns a snapshot of all sessions.
func (m *Manager) ListSessions() []Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Session, 0, len(m.terminals))
	for _, mg := range m.terminals {
		out = append(out, *mg.session)
	}
	return out
}

// ListForAccount returns an account's sessions.
func (m *Manager) ListForAccount(accountID string) []Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Session, 0)
	for _, mg := range m.terminals {
		if mg.session.AccountID == accountID {
			out = append(out, *mg.session)
		}
	}
	return out
}

// EndpointIDsForAccount lists endpoint ids an account has open sessions on
// (satisfies rest.SessionLister for the endpoint-delete guard).
func (m *Manager) EndpointIDsForAccount(accountID string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []string
	for _, mg := range m.terminals {
		if mg.session.AccountID == accountID {
			ids = append(ids, mg.session.EndpointID)
		}
	}
	return ids
}

// GetSession returns a session snapshot, or nil.
func (m *Manager) GetSession(sessionID string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	mg, ok := m.terminals[sessionID]
	if !ok {
		return nil
	}
	s := *mg.session
	return &s
}

// Close closes a session with a reason.
func (m *Manager) Close(sessionID string, reason CloseReason) {
	mg, err := m.get(sessionID)
	if err != nil {
		return
	}
	m.setStatus(mg, StatusClosing, reason)
	_ = mg.transport.Close()
}

// CloseAllForAccount closes an account's sessions (returns count).
func (m *Manager) CloseAllForAccount(accountID string, reason CloseReason) int {
	m.mu.Lock()
	ids := make([]string, 0)
	for id, mg := range m.terminals {
		if mg.session.AccountID == accountID {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	for _, id := range ids {
		m.Close(id, reason)
	}
	return len(ids)
}

// Destroy closes all sessions (shutdown).
func (m *Manager) Destroy() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.terminals))
	for id := range m.terminals {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	for _, id := range ids {
		m.Close(id, CloseShutdown)
	}
}

func (m *Manager) get(sessionID string) (*managed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mg, ok := m.terminals[sessionID]
	if !ok {
		return nil, fmt.Errorf("terminal %s not found", sessionID)
	}
	return mg, nil
}

// setStatus transitions a session and fires guaranteed status hooks. Terminal
// states remove the session from the registry (after the hook, so subscribers
// see the final transition).
func (m *Manager) setStatus(mg *managed, status Status, reason CloseReason) {
	m.mu.Lock()
	prev := mg.session.Status
	if prev == status {
		m.mu.Unlock()
		return
	}
	mg.session.Status = status
	if reason != "" && mg.session.CloseReason == "" {
		mg.session.CloseReason = reason
	}
	terminal := status == StatusClosed || status == StatusError
	if terminal {
		delete(m.terminals, mg.session.SessionID)
		mg.output.Clear()
	}
	subs := make([]func(StatusEvent), 0, len(m.statusSubs))
	for _, fn := range m.statusSubs {
		subs = append(subs, fn)
	}
	ev := StatusEvent{SessionID: mg.session.SessionID, Status: status, Previous: prev, Reason: mg.session.CloseReason}
	m.mu.Unlock()

	for _, fn := range subs {
		fn(ev)
	}
}

var _ = time.Now
