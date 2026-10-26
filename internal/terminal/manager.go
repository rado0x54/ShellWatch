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
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
)

type managed struct {
	session *Session
	// transport is nil until Create's factory returns (the session is
	// registered first so sweeps can find it); non-nil from before the Open
	// broadcast on. Guarded by Manager.mu.
	transport Transport
	output    *OutputBuffer
	// pumpDone closes when the pump goroutine exits; Close joins it so the
	// Closed broadcast always sees every event the transport delivered.
	pumpDone chan struct{}
	// abandoned is set when Close gave up joining the pump (wedged transport):
	// the still-running pump must discard events instead of refilling a
	// buffer the close already cleared (memory for a session that is gone —
	// possibly a deleted account's).
	abandoned atomic.Bool
	// cancelSetup aborts the in-flight transport factory (connection + human
	// approval wait); non-nil only while Create is inside the factory.
	// Guarded by Manager.mu. Close calls it so revocation, account deletion,
	// and shutdown reach sessions that are still connecting.
	cancelSetup context.CancelFunc
}

// StatusEvent is emitted on every status transition (guaranteed, ordered).
// CreatedAt is carried so close-side subscribers (audit duration_ms) still see
// it after a terminal transition removed the session from the registry.
type StatusEvent struct {
	SessionID string
	Status    Status
	Previous  Status
	Reason    CloseReason
	CreatedAt time.Time
}

// DefaultIdleTimeout matches Node's DEFAULT_IDLE_TIMEOUT (terminal-manager.ts).
const DefaultIdleTimeout = 30 * time.Minute

// DefaultIdleSweepInterval matches Node's DEFAULT_CLEANUP_INTERVAL.
const DefaultIdleSweepInterval = time.Minute

// Manager owns all sessions.
type Manager struct {
	mu            sync.Mutex
	destroyed     bool // set by Destroy: Create refuses, no session can outlive shutdown
	terminals     map[string]*managed
	factory       TransportFactory
	clk           clock.Clock
	maxBufferSize int
	idleTimeout   time.Duration

	statusSubs  map[int]func(StatusEvent)
	outputSubs  map[int]func(sessionID string, offset int64)
	removedSubs map[int]func(sessionID string)
	nextSub     int

	// closeJoinTimeout bounds Close's pump join (liveness: a wedged transport
	// teardown must not stall the idle janitor / shutdown / every other close
	// behind it). Tests shorten it.
	closeJoinTimeout time.Duration
}

// NewManager builds a Manager. factory establishes transports.
func NewManager(factory TransportFactory, clk clock.Clock, maxBufferSize int) *Manager {
	if clk == nil {
		clk = clock.Real{}
	}
	return &Manager{
		terminals: map[string]*managed{}, factory: factory, clk: clk,
		maxBufferSize:    maxBufferSize,
		idleTimeout:      DefaultIdleTimeout,
		statusSubs:       map[int]func(StatusEvent){},
		outputSubs:       map[int]func(string, int64){},
		removedSubs:      map[int]func(string){},
		closeJoinTimeout: 5 * time.Second,
	}
}

// SetIdleTimeout overrides the idle timeout (tests; <=0 disables the sweep).
func (m *Manager) SetIdleTimeout(d time.Duration) {
	m.mu.Lock()
	m.idleTimeout = d
	m.mu.Unlock()
}

// RunIdleJanitor sweeps idle-open sessions on interval until ctx is done
// (port of cleanupIdleTerminals + its setInterval).
func (m *Manager) RunIdleJanitor(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultIdleSweepInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.SweepIdle()
		}
	}
}

// SweepIdle closes open sessions whose last activity is older than the idle
// timeout (reason idle-timeout).
func (m *Manager) SweepIdle() {
	m.mu.Lock()
	timeout := m.idleTimeout
	if timeout <= 0 {
		m.mu.Unlock()
		return
	}
	now := m.clk.Now()
	var ids []string
	for id, mg := range m.terminals {
		if mg.session.Status != StatusOpen {
			continue
		}
		if now.Sub(mg.session.LastActivityAt) > timeout {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	m.closeAll(ids, CloseIdleTimeout)
}

// closeAll closes sessions concurrently: each Close's pump join is bounded by
// closeJoinTimeout, and closing serially would stack those bounds (20 wedged
// transports = 20x the bound stalling shutdown or a janitor sweep).
func (m *Manager) closeAll(ids []string, reason CloseReason) {
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Close(id, reason)
		}()
	}
	wg.Wait()
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

// SubscribeRemoved registers a hook fired after a session is removed from
// the registry (explicit close, account purge). The WS hub uses it to sweep
// connections whose attach raced the removal: the Closed broadcast happens
// before the delete (so the tail drain can still read the buffer), which
// leaves a window where an attach lands on a session about to disappear.
func (m *Manager) SubscribeRemoved(fn func(sessionID string)) func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextSub
	m.nextSub++
	m.removedSubs[id] = fn
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.removedSubs, id)
	}
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
		sess.OwnerClientID = trigger.OwnerClientID
		sess.MCPReason = trigger.Reason
		sess.MCPClientName = trigger.MCPClientName
		sess.MCPClientVer = trigger.MCPClientVer
	}

	// Register BEFORE the factory runs: connecting can block for minutes
	// (human approval of the SSH signature), and every sweep — consent
	// revocation, account deletion, Destroy — must find a session that is
	// still connecting and be able to cancel it. Close on a registered entry
	// with no transport cancels setupCtx; the tail below finalizes.
	setupCtx, cancelSetup := context.WithCancel(ctx)
	defer cancelSetup()
	mg := &managed{session: sess, output: NewOutputBuffer(m.maxBufferSize), pumpDone: make(chan struct{}), cancelSetup: cancelSetup}
	m.mu.Lock()
	if m.destroyed {
		// Destroy already snapshotted the registry: registering now would
		// create a session nothing ever closes (an in-flight create request
		// racing shutdown). Refuse at the owner — HTTP-layer ordering
		// (srv.Close before Destroy) narrows this window but cannot close it.
		m.mu.Unlock()
		return nil, fmt.Errorf("server is shutting down")
	}
	m.terminals[sess.SessionID] = mg
	m.mu.Unlock()

	transport, err := m.factory(setupCtx, FactoryParams{Endpoint: ep, SessionID: sess.SessionID, Trigger: trigger})

	// Adopt the transport and the abort check in one critical section: a
	// Close that already moved the session to closing owns its fate — the
	// transport must not be adopted after that, or nothing would close it.
	m.mu.Lock()
	mg.cancelSetup = nil
	aborted := sess.Status != StatusOpening // a Close raced the setup
	if err == nil && !aborted {
		mg.transport = transport
	}
	m.mu.Unlock()

	if err != nil {
		if aborted {
			// beginClosing already broadcast closing; balance it with closed
			// (before removal, same ordering invariant as Close).
			m.setStatus(mg, StatusClosed, "")
		}
		// No lifecycle was broadcast otherwise — the session never opened.
		m.removeEntry(sess.SessionID)
		return nil, fmt.Errorf("Failed to connect to %s: %w", ep.ID, err)
	}
	if aborted {
		// The factory outran the cancellation (or ignored it) — the revoked /
		// deleted / shut-down session must not go live now.
		_ = transport.Close()
		m.setStatus(mg, StatusClosed, "")
		m.removeEntry(sess.SessionID)
		return nil, fmt.Errorf("session was closed during connection setup (%s)", sess.CloseReason)
	}

	// Open BEFORE the pump starts (and snapshot before it can touch the
	// session): a transport that dies immediately finalizes the session from
	// the pump, and a terminal state must never be flipped back to open —
	// setStatus guards that too, this ordering just makes it impossible here.
	m.setStatus(mg, StatusOpen, "")
	// Snapshot under the lock: the open broadcast above can prompt a client
	// to close the session from another goroutine before Create returns.
	m.mu.Lock()
	out := *sess
	m.mu.Unlock()
	go func() {
		defer close(mg.pumpDone)
		m.pump(mg)
	}()
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
			m.setStatus(mg, StatusError, m.reasonOr(mg, CloseTransportError))
			return
		case ev.Closed:
			m.setStatus(mg, StatusClosed, m.reasonOr(mg, CloseServerHangup))
			return
		default:
			if mg.abandoned.Load() {
				continue // close timed out and moved on; drop, don't refill
			}
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
	m.setStatus(mg, StatusClosed, m.reasonOr(mg, CloseServerHangup))
}

// reasonOr reads the stamped close reason under the lock (setStatus /
// beginClosing write it under the same lock — the pump calls this
// concurrently with an explicit Close).
func (m *Manager) reasonOr(mg *managed, fallback CloseReason) CloseReason {
	m.mu.Lock()
	defer m.mu.Unlock()
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
	if err := mg.transport.Write([]byte(input)); err != nil {
		return err
	}
	m.mu.Lock()
	mg.session.LastActivityAt = m.clk.Now()
	m.mu.Unlock()
	return nil
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
	m.mu.Lock()
	transport := mg.transport
	status := mg.session.Status
	m.mu.Unlock()
	if transport == nil {
		// Still connecting — registered before the factory finished.
		return fmt.Errorf("terminal %s is not open (status: %s)", sessionID, status)
	}
	return transport.Resize(cols, rows)
}

// ListSessions returns a snapshot of all non-closed sessions. Closed sessions
// are retained in the registry (post-mortem tail/re-attach) but hidden from
// lists; errored ones stay visible (listSessions filter, terminal-manager.ts).
func (m *Manager) ListSessions() []Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Session, 0, len(m.terminals))
	for _, mg := range m.terminals {
		if mg.session.Status == StatusClosed {
			continue
		}
		out = append(out, *mg.session)
	}
	return out
}

// ListForAccount returns an account's non-closed sessions.
func (m *Manager) ListForAccount(accountID string) []Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Session, 0)
	for _, mg := range m.terminals {
		if mg.session.AccountID == accountID && mg.session.Status != StatusClosed {
			out = append(out, *mg.session)
		}
	}
	return out
}

// CountOpenForAccount counts the account's status-open sessions — the REST
// session-cap semantics: account-wide, UI and MCP sessions alike. (The MCP
// cap in agent.Session deliberately differs: it counts only that agent's own
// live sessions.)
func (m *Manager) CountOpenForAccount(accountID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, mg := range m.terminals {
		if mg.session.AccountID == accountID && mg.session.Status == StatusOpen {
			n++
		}
	}
	return n
}

// EndpointIDsForAccount lists endpoint ids an account has non-closed sessions
// on (satisfies rest.SessionLister for the endpoint-delete guard).
func (m *Manager) EndpointIDsForAccount(accountID string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []string
	for _, mg := range m.terminals {
		if mg.session.AccountID == accountID && mg.session.Status != StatusClosed {
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

// Close explicitly closes a session: transport down, buffer cleared, removed
// from the registry (terminal-manager.ts close()). No-op when already
// closed/closing — a retained post-mortem session stays readable until the
// process ends, mirroring Node.
func (m *Manager) Close(sessionID string, reason CloseReason) {
	mg, err := m.get(sessionID)
	if err != nil {
		return
	}
	// The guard and the closing transition must be one atomic step: a
	// transport-driven Closed from the pump racing this call must either win
	// (we bail) or lose (it becomes the normal closing->closed step) — never
	// interleave into a closed->closing regression.
	if !m.beginClosing(mg, reason) {
		return
	}
	m.mu.Lock()
	cancelSetup := mg.cancelSetup
	transport := mg.transport
	m.mu.Unlock()
	if transport == nil {
		// The session is still connecting (Create is inside the factory).
		// Cancel the setup; Create's tail observes the closing status, closes
		// any transport the factory still returns, broadcasts closed, and
		// removes the entry.
		if cancelSetup != nil {
			cancelSetup()
		}
		return
	}
	_ = transport.Close()
	// Join the pump: it drains every event the transport already delivered
	// (appending data and notifying output subscribers, in order) and then
	// broadcasts Closed itself on the way out — so the Closed broadcast, and
	// the WS hub's tail drain inside it, always see the complete buffer. The
	// broadcast also happens BEFORE Clear below: clearing first made the
	// drain observe the offset rewinding and emit a reset frame that blanked
	// the client's terminal on every explicit close.
	joinTimeout, stopTimer := m.clk.After(m.closeJoinTimeout)
	select {
	case <-mg.pumpDone:
		stopTimer()
	case <-joinTimeout:
		// Liveness over completeness: the transport broke its contract
		// (Close must terminate Events). Mark the pump abandoned so it
		// discards further events instead of refilling the cleared buffer,
		// and proceed — the tail may be incomplete and the goroutine leaks,
		// but the janitor, shutdown, and every other close stay unblocked.
		mg.abandoned.Store(true)
		slog.Warn("terminal close: pump did not drain in time; proceeding", "session", sessionID)
	}
	// On the join path the pump finalized Closed itself; on the timeout path
	// this is what finalizes it.
	m.setStatus(mg, StatusClosed, reason)
	m.removeEntry(sessionID)
}

// removeEntry clears a registered session's buffer and deletes it from the
// registry in one critical section (no reader can observe a cleared-but-
// still-listed session), then fires the removed hooks. The hooks fire only
// when THIS call performed the delete — a concurrent RemoveForAccount may
// have won, and each removal must notify exactly once (the WS hub sweep keys
// on it).
func (m *Manager) removeEntry(sessionID string) {
	m.mu.Lock()
	mg, present := m.terminals[sessionID]
	var removed []func(string)
	if present {
		mg.output.Clear()
		delete(m.terminals, sessionID)
		removed = make([]func(string), 0, len(m.removedSubs))
		for _, fn := range m.removedSubs {
			removed = append(removed, fn)
		}
	}
	m.mu.Unlock()
	for _, fn := range removed {
		fn(sessionID)
	}
}

// beginClosing atomically checks the status and transitions to closing,
// firing status hooks; false when the session is already closing/closed.
func (m *Manager) beginClosing(mg *managed, reason CloseReason) bool {
	m.mu.Lock()
	prev := mg.session.Status
	if prev == StatusClosed || prev == StatusClosing {
		m.mu.Unlock()
		return false
	}
	mg.session.Status = StatusClosing
	if reason != "" && mg.session.CloseReason == "" {
		mg.session.CloseReason = reason
	}
	subs := make([]func(StatusEvent), 0, len(m.statusSubs))
	for _, fn := range m.statusSubs {
		subs = append(subs, fn)
	}
	ev := StatusEvent{SessionID: mg.session.SessionID, Status: StatusClosing, Previous: prev, Reason: mg.session.CloseReason, CreatedAt: mg.session.CreatedAt}
	m.mu.Unlock()
	for _, fn := range subs {
		fn(ev)
	}
	return true
}

// CloseAllForAccount closes an account's non-closed sessions (returns count).
func (m *Manager) CloseAllForAccount(accountID string, reason CloseReason) int {
	m.mu.Lock()
	ids := make([]string, 0)
	for id, mg := range m.terminals {
		if mg.session.AccountID == accountID && mg.session.Status != StatusClosed {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	m.closeAll(ids, reason)
	return len(ids)
}

// CloseAllForClient closes an account's non-closed MCP sessions owned by the
// given OAuth client (consent revocation, #243). An empty clientID matches
// every MCP client of the account (revoke-all). Returns the count.
func (m *Manager) CloseAllForClient(accountID, clientID string, reason CloseReason) int {
	m.mu.Lock()
	ids := make([]string, 0)
	for id, mg := range m.terminals {
		s := mg.session
		if s.AccountID == accountID && s.Source == SourceMCP && s.Status != StatusClosed &&
			(clientID == "" || s.OwnerClientID == clientID) {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	m.closeAll(ids, reason)
	return len(ids)
}

// OutputOffset returns the offset past the last buffered output byte.
func (m *Manager) OutputOffset(sessionID string) (int64, error) {
	mg, err := m.get(sessionID)
	if err != nil {
		return 0, err
	}
	return mg.output.CurrentOffset(), nil
}

// RemoveForAccount drops an account's retained post-mortem (closed/errored)
// sessions from the registry and releases their buffers. Account deletion
// must not leave a deleted account's terminal output readable in memory —
// CloseAllForAccount skips already-closed sessions, so the H1 teardown calls
// this afterwards. Returns the number removed.
func (m *Manager) RemoveForAccount(accountID string) int {
	m.mu.Lock()
	ids := make([]string, 0)
	for id, mg := range m.terminals {
		if mg.session.AccountID != accountID {
			continue
		}
		if mg.session.Status == StatusClosed || mg.session.Status == StatusError {
			mg.output.Clear()
			delete(m.terminals, id)
			ids = append(ids, id)
		}
	}
	removed := make([]func(string), 0, len(m.removedSubs))
	for _, fn := range m.removedSubs {
		removed = append(removed, fn)
	}
	m.mu.Unlock()
	for _, id := range ids {
		for _, fn := range removed {
			fn(id)
		}
	}
	return len(ids)
}

// Destroy closes all sessions (shutdown) and marks the manager destroyed:
// the flag is set under the same lock the id snapshot is taken under, so any
// Create either registered before the snapshot (and is closed here) or
// observes the flag and refuses — no session can be created after Destroy.
func (m *Manager) Destroy() {
	m.mu.Lock()
	m.destroyed = true
	ids := make([]string, 0, len(m.terminals))
	for id := range m.terminals {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	m.closeAll(ids, CloseShutdown)
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
// transitions do NOT remove the session — transport-driven closes/errors keep
// it registered (with its buffer) so the final output stays readable; only an
// explicit Close() removes it (setStatus in terminal-manager.ts, M6).
func (m *Manager) setStatus(mg *managed, status Status, reason CloseReason) {
	m.mu.Lock()
	prev := mg.session.Status
	// Same-status no-op; closed/error are absorbing, and closing absorbs an
	// Open — Destroy or an account deletion can hit a session between Create
	// registering it and Create's setStatus(Open), and the session must not
	// broadcast closing -> open -> closed (a dead session resurrecting).
	if prev == status || prev == StatusClosed || prev == StatusError ||
		(prev == StatusClosing && status == StatusOpen) {
		m.mu.Unlock()
		return
	}
	mg.session.Status = status
	if reason != "" && mg.session.CloseReason == "" {
		mg.session.CloseReason = reason
	}
	subs := make([]func(StatusEvent), 0, len(m.statusSubs))
	for _, fn := range m.statusSubs {
		subs = append(subs, fn)
	}
	ev := StatusEvent{SessionID: mg.session.SessionID, Status: status, Previous: prev, Reason: mg.session.CloseReason, CreatedAt: mg.session.CreatedAt}
	m.mu.Unlock()

	for _, fn := range subs {
		fn(ev)
	}
}
