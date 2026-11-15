// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package transfer is the MCP file-transfer service (#263). Both tiers run
// over the SFTP subsystem on the already-approved SSH connection of an open
// session — no new signature, no new approval:
//
//   - inline (inline.go): list/read/write of small files through tool calls,
//     over one lazily opened SFTP channel per session;
//   - link (link.go): a short-lived, single-use URL the agent's host moves
//     the bytes through out of band (PUT/GET /api/transfers/{token}), staged
//     and committed atomically on upload.
//
// This file owns what both share: the in-memory token/status store with its
// limits and janitor, the state machine, the lifecycle subscription to the
// terminal Manager, the audit write-ahead, and the terminal:file fan-out.
// Tokens and live transfers are process memory by design (single-instance,
// like pending actions); the audit row is the durable record.
package transfer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"

	"github.com/rado0x54/shellwatch/internal/audit"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// State is a transfer's lifecycle state.
//
//	pending → active → committing → completed | failed
//	pending → expired | cancelled        active → failed | cancelled
//
// committing is the point of no return for cancellation (uploads only). It is
// persisted in the audit row but reported as "active" to agents and browsers.
type State string

const (
	StatePending    State = "pending"
	StateActive     State = "active"
	StateCommitting State = "committing"
	StateCompleted  State = "completed"
	StateFailed     State = "failed"
	StateCancelled  State = "cancelled"
	StateExpired    State = "expired"
)

func (s State) finished() bool {
	return s == StateCompleted || s == StateFailed || s == StateCancelled || s == StateExpired
}

// external maps the internal state to the one the wire contract exposes.
func (s State) external() string {
	if s == StateCommitting {
		return string(StateActive)
	}
	return string(s)
}

const (
	TierInline = "inline"
	TierLink   = "link"

	DirectionUpload   = "upload"
	DirectionDownload = "download"
	DirectionList     = "list"

	CommitOK      = "ok"
	CommitFailed  = "failed"
	CommitUnknown = "unknown"

	CleanupOK     = "ok"
	CleanupFailed = "failed"
)

// progressInterval debounces terminal:file progress frames and the session
// activity touch (same order of magnitude as the output notifier).
const progressInterval = 250 * time.Millisecond

// Extensions a link upload requires: without both there is no atomic
// no-clobber commit and no atomic replace, and there is no fallback.
const (
	extPosixRename = "posix-rename@openssh.com"
	extHardlink    = "hardlink@openssh.com"
)

// Caller identifies who is asking: the authenticated (account, OAuth client)
// plus the client-reported MCP name/version for attribution.
type Caller struct {
	AccountID     string
	ClientID      string
	ClientName    string
	ClientVersion string
	SourceIP      string
}

// View is an immutable snapshot of one transfer.
type View struct {
	TransferID string
	AccountID  string
	SessionID  string
	EndpointID string
	Tier       string
	Direction  string
	Path       string
	Status     State
	Bytes      int64
	// TotalBytes is the expected size when known (-1 otherwise).
	TotalBytes    int64
	SHA256        string
	Error         string
	Truncated     *bool
	CommitOutcome string
	Cleanup       string
	StagingPath   string
	ClientID      string
	ClientName    string
	ClientVersion string
	SourceIP      string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	ExpiresAt     time.Time // link transfers: deadline to claim
	FinishedAt    time.Time
}

// Event is the terminal:file WebSocket frame for this snapshot.
func (v View) Event() map[string]any {
	ev := map[string]any{
		"type": "terminal:file", "sessionId": v.SessionID, "transferId": v.TransferID,
		"direction": v.Direction, "path": v.Path, "bytes": v.Bytes,
		"status": v.Status.external(), "tier": v.Tier, "mcpClientName": v.ClientName,
	}
	v.addOutcome(ev)
	return ev
}

// StatusResult is the shellwatch_transfer_file status/cancel result.
func (v View) StatusResult() map[string]any {
	res := map[string]any{
		"transferId": v.TransferID, "status": v.Status.external(),
		"direction": v.Direction, "path": v.Path, "bytes": v.Bytes,
	}
	v.addOutcome(res)
	return res
}

func (v View) addOutcome(m map[string]any) {
	if v.TotalBytes >= 0 {
		m["totalBytes"] = v.TotalBytes
	}
	if v.SHA256 != "" {
		m["sha256"] = v.SHA256
	}
	if v.Error != "" {
		m["error"] = v.Error
	}
	if v.Truncated != nil {
		m["truncated"] = *v.Truncated
	}
	if v.CommitOutcome != "" {
		m["commitOutcome"] = v.CommitOutcome
	}
	if v.Cleanup != "" {
		m["cleanup"] = v.Cleanup
	}
	if v.StagingPath != "" {
		m["stagingPath"] = v.StagingPath
	}
}

func (v View) auditRow() audit.FileTransferRow {
	opt := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}
	row := audit.FileTransferRow{
		TransferID: v.TransferID, AccountID: v.AccountID, SessionID: v.SessionID, EndpointID: v.EndpointID,
		Tier: v.Tier, Direction: v.Direction, Path: v.Path, Status: string(v.Status), Bytes: v.Bytes,
		SHA256: opt(v.SHA256), Error: opt(v.Error), Truncated: v.Truncated,
		CommitOutcome: opt(v.CommitOutcome), Cleanup: opt(v.Cleanup), StagingPath: opt(v.StagingPath),
		ClientID: opt(v.ClientID), MCPClientName: opt(v.ClientName), MCPClientVersion: opt(v.ClientVersion),
		SourceIP:  opt(v.SourceIP),
		CreatedAt: v.CreatedAt.UTC().Format(clock.ISOMillis),
		UpdatedAt: v.UpdatedAt.UTC().Format(clock.ISOMillis),
	}
	if v.TotalBytes >= 0 {
		total := v.TotalBytes
		row.TotalBytes = &total
	}
	if !v.FinishedAt.IsZero() {
		row.FinishedAt = opt(v.FinishedAt.UTC().Format(clock.ISOMillis))
	}
	return row
}

// viewFromRow rebuilds a snapshot from the audit row (status after eviction).
func viewFromRow(r *audit.FileTransferRow) View {
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	v := View{
		TransferID: r.TransferID, AccountID: r.AccountID, SessionID: r.SessionID, EndpointID: r.EndpointID,
		Tier: r.Tier, Direction: r.Direction, Path: r.Path, Status: State(r.Status), Bytes: r.Bytes,
		TotalBytes: -1, SHA256: str(r.SHA256), Error: str(r.Error), Truncated: r.Truncated,
		CommitOutcome: str(r.CommitOutcome), Cleanup: str(r.Cleanup), StagingPath: str(r.StagingPath),
		ClientID: str(r.ClientID), ClientName: str(r.MCPClientName), ClientVersion: str(r.MCPClientVersion),
	}
	if r.TotalBytes != nil {
		v.TotalBytes = *r.TotalBytes
	}
	return v
}

// AuditLog is the durable record (satisfied by *audit.FileTransfers).
type AuditLog interface {
	Save(row audit.FileTransferRow)
	Get(ctx context.Context, accountID, transferID string) (*audit.FileTransferRow, error)
}

// Publisher delivers a frame to every browser connection attached to a
// session (satisfied by *ws.Hub).
type Publisher interface {
	SendToSession(sessionID string, msg any)
}

// Params are the service's collaborators.
type Params struct {
	Manager *terminal.Manager
	Limits  config.Transfer
	Clock   clock.Clock
	// Audit may be nil (tests): nothing is persisted and status after
	// eviction answers "not found".
	Audit AuditLog
	// Publisher may be nil, and may be set later via SetPublisher.
	Publisher Publisher
	// OnFailed fires once for every link transfer that ends failed or
	// expired, after its cleanup settled (the notification hook). May be nil.
	OnFailed func(View)
	// ExternalURL is the public origin transfer links are minted under.
	ExternalURL func() string
}

// xfer is a link transfer's mutable record. Every field is guarded by
// Service.mu.
type xfer struct {
	View
	token     string
	maxBytes  int64
	expectSHA string
	overwrite bool
	mode      *os.FileMode

	// Set at claim: cancel aborts the request context, interrupt unblocks a
	// handler stuck in HTTP body I/O.
	cancel    context.CancelFunc
	interrupt func()
	// claimed transfers are owned by their HTTP handler, which settles
	// cleanup and fires OnFailed; unclaimed ones are finalized by the aborter.
	claimed      bool
	lastProgress time.Time
	lastPublish  time.Time
}

// Service is the transfer store + both tiers.
type Service struct {
	mgr   *terminal.Manager
	lim   config.Transfer
	clk   clock.Clock
	audit AuditLog
	p     Params

	// emitMu orders persist+publish per snapshot: each emission re-reads the
	// current state under mu while holding emitMu, so a stale snapshot can
	// never be delivered after a newer one. Lock order: emitMu, then mu.
	emitMu sync.Mutex

	mu       sync.Mutex
	pub      Publisher
	byID     map[string]*xfer
	byToken  map[string]*xfer
	sessions map[string]*sessionFS

	unsubStatus  func()
	unsubRemoved func()

	// beforeCommit is a test seam: it runs after the transfer entered
	// committing and before the commit call is issued.
	beforeCommit func(transferID string, client *sftp.Client)
}

// New builds the service and subscribes it to the Manager's session lifecycle.
func New(p Params) *Service {
	if p.Clock == nil {
		p.Clock = clock.Real{}
	}
	if p.ExternalURL == nil {
		p.ExternalURL = func() string { return "" }
	}
	s := &Service{
		mgr: p.Manager, lim: p.Limits.WithDefaults(), clk: p.Clock, audit: p.Audit, p: p, pub: p.Publisher,
		byID: map[string]*xfer{}, byToken: map[string]*xfer{}, sessions: map[string]*sessionFS{},
	}
	s.unsubStatus = p.Manager.SubscribeStatus(s.onSessionStatus)
	s.unsubRemoved = p.Manager.SubscribeRemoved(s.dropSession)
	return s
}

// SetPublisher wires the WS fan-out after construction (the hub and this
// service are built in either order at the composition root).
func (s *Service) SetPublisher(p Publisher) {
	s.mu.Lock()
	s.pub = p
	s.mu.Unlock()
}

// Close detaches the Manager subscriptions.
func (s *Service) Close() {
	s.unsubStatus()
	s.unsubRemoved()
}

// Limits returns the effective limits (defaults applied).
func (s *Service) Limits() config.Transfer { return s.lim }

// RunJanitor sweeps expired links and stale status records until ctx ends.
func (s *Service) RunJanitor(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Sweep()
		}
	}
}

// Sweep expires pending links past their TTL and evicts finished records
// past statusRetentionSeconds.
func (s *Service) Sweep() {
	now := s.clk.Now()
	retention := time.Duration(s.lim.StatusRetentionSeconds) * time.Second
	s.mu.Lock()
	var expired []*xfer
	for id, x := range s.byID {
		switch {
		case x.Status == StatePending && !now.Before(x.ExpiresAt):
			expired = append(expired, x)
		case x.Status.finished() && now.Sub(x.FinishedAt) >= retention:
			delete(s.byID, id)
		}
	}
	s.mu.Unlock()
	for _, x := range expired {
		s.abort(x, StateExpired, "link expired before it was used")
	}
}

// SnapshotTo hands deliver a terminal:file frame for every unfinished link
// transfer of a session, so a browser that just attached reconstructs the
// transfer strip. deliver runs while emissions are held back (emitMu): the
// caller must already be subscribed to the session's frames, and then no
// frame can fall between the snapshot and the subscription — a transfer that
// changes state concurrently is either reflected in the snapshot, or its
// frame is delivered after it. Taking the snapshot before subscribing would
// lose a final frame and leave the transfer shown as unfinished.
func (s *Service) SnapshotTo(sessionID string, deliver func(frames []any)) {
	s.emitMu.Lock()
	defer s.emitMu.Unlock()
	deliver(s.Snapshot(sessionID))
}

// Snapshot returns the frames SnapshotTo delivers, without the ordering
// guarantee.
func (s *Service) Snapshot(sessionID string) []any {
	s.mu.Lock()
	var views []View
	for _, x := range s.byID {
		if x.SessionID == sessionID && !x.Status.finished() {
			views = append(views, x.View)
		}
	}
	s.mu.Unlock()
	sort.Slice(views, func(i, j int) bool { return views[i].CreatedAt.Before(views[j].CreatedAt) })
	out := make([]any, 0, len(views))
	for _, v := range views {
		out = append(out, v.Event())
	}
	return out
}

// --- session lifecycle ---

// onSessionStatus invalidates a session's transfers the moment it leaves
// open: explicit close, idle janitor, consent revocation and account deletion
// all pass through closing (→ cancelled); a remote hangup or transport error
// goes straight to closed/error (→ active transfers failed).
func (s *Service) onSessionStatus(ev terminal.StatusEvent) {
	switch ev.Status {
	case terminal.StatusClosing:
		s.endSession(ev.SessionID, StateCancelled, "session closed")
	case terminal.StatusClosed, terminal.StatusError:
		reason := string(ev.Reason)
		if reason == "" {
			reason = string(ev.Status)
		}
		s.endSession(ev.SessionID, StateFailed, "session ended ("+reason+")")
	}
}

func (s *Service) endSession(sessionID string, activeState State, msg string) {
	s.mu.Lock()
	var hit []*xfer
	for _, x := range s.byID {
		if x.SessionID == sessionID && (x.Status == StatePending || x.Status == StateActive) {
			hit = append(hit, x)
		}
	}
	s.mu.Unlock()
	for _, x := range hit {
		s.mu.Lock()
		state := StateCancelled // unclaimed links are simply invalidated
		if x.Status == StateActive {
			state = activeState
		}
		s.mu.Unlock()
		s.abort(x, state, msg)
	}
	s.dropSession(sessionID)
}

// --- state machine ---

// abort moves a pending or active transfer to a terminal state. It is the
// only way out of those states other than a commit, and it loses against a
// commit that was already issued: once a transfer is committing, abort is a
// no-op and the outcome is whatever the commit reports. Returns whether this
// call performed the transition.
func (s *Service) abort(x *xfer, state State, msg string) bool {
	return s.terminate(x, state, msg, true)
}

// fail is abort(StateFailed) issued by the transfer's own request handler:
// same transition, but the handler is not interrupted — it is the one
// reporting the failure and still has a response to write.
func (s *Service) fail(x *xfer, msg string) bool {
	return s.terminate(x, StateFailed, msg, false)
}

func (s *Service) terminate(x *xfer, state State, msg string, interruptHandler bool) bool {
	s.mu.Lock()
	if x.Status != StatePending && x.Status != StateActive {
		s.mu.Unlock()
		return false
	}
	now := s.clk.Now()
	x.Status = state
	x.Error = msg
	x.UpdatedAt, x.FinishedAt = now, now
	delete(s.byToken, x.token)
	cancel, interrupt, claimed := x.cancel, x.interrupt, x.claimed
	v := x.View
	s.mu.Unlock()
	logTransfer(v)

	if interruptHandler {
		if cancel != nil {
			cancel()
		}
		if interrupt != nil {
			interrupt()
		}
	}
	s.emit(x, true)
	if !claimed {
		s.notifyFailed(x)
	}
	return true
}

// beginCommit atomically moves active → committing; false means an abort won
// the race and the commit must not be issued.
func (s *Service) beginCommit(x *xfer) bool {
	s.mu.Lock()
	if x.Status != StateActive {
		s.mu.Unlock()
		return false
	}
	x.Status = StateCommitting
	x.UpdatedAt = s.clk.Now()
	s.mu.Unlock()
	s.emit(x, true) // audit row written ahead of the commit call
	return true
}

// finish records the outcome of a transfer its handler carried to the end
// (from committing for uploads, from active for downloads). A no-op when an
// abort already finalized it.
func (s *Service) finish(x *xfer, state State, mutate func(v *View)) bool {
	s.mu.Lock()
	if x.Status != StateActive && x.Status != StateCommitting {
		s.mu.Unlock()
		return false
	}
	now := s.clk.Now()
	x.Status = state
	x.UpdatedAt, x.FinishedAt = now, now
	if mutate != nil {
		mutate(&x.View)
	}
	v := x.View
	s.mu.Unlock()
	logTransfer(v)
	s.emit(x, true)
	return true
}

// update applies a non-state mutation (staging path, cleanup result, total
// size) and emits it.
func (s *Service) update(x *xfer, mutate func(v *View)) {
	s.mu.Lock()
	mutate(&x.View)
	x.UpdatedAt = s.clk.Now()
	s.mu.Unlock()
	s.emit(x, true)
}

func (s *Service) view(x *xfer) View {
	s.mu.Lock()
	defer s.mu.Unlock()
	return x.View
}

// emit persists (optionally) and publishes the transfer's CURRENT snapshot.
func (s *Service) emit(x *xfer, persist bool) {
	s.emitMu.Lock()
	defer s.emitMu.Unlock()
	s.mu.Lock()
	v := x.View
	x.lastPublish = s.clk.Now()
	pub := s.pub
	s.mu.Unlock()
	if persist && s.audit != nil {
		s.audit.Save(v.auditRow())
	}
	if pub != nil {
		pub.SendToSession(v.SessionID, v.Event())
	}
}

// emitView records a transfer that never lives in the store (inline tier).
func (s *Service) emitView(v View) {
	s.emitMu.Lock()
	defer s.emitMu.Unlock()
	if s.audit != nil {
		s.audit.Save(v.auditRow())
	}
	s.mu.Lock()
	pub := s.pub
	s.mu.Unlock()
	if pub != nil {
		pub.SendToSession(v.SessionID, v.Event())
	}
}

// progress accounts moved bytes; the WS frame and the session activity touch
// are coalesced to one per progressInterval.
func (s *Service) progress(x *xfer, n int64) {
	now := s.clk.Now()
	s.mu.Lock()
	x.Bytes += n
	first := x.lastProgress.IsZero()
	x.lastProgress = now
	due := first || now.Sub(x.lastPublish) >= progressInterval
	sessionID := x.SessionID
	s.mu.Unlock()
	if due {
		// Real progress keeps the session alive: the Manager's idle sweep only
		// sees PTY traffic.
		s.mgr.TouchActivity(sessionID)
		s.emit(x, false)
	}
}

func (s *Service) notifyFailed(x *xfer) {
	if s.p.OnFailed == nil {
		return
	}
	v := s.view(x)
	if v.Tier == TierLink && (v.Status == StateFailed || v.Status == StateExpired) {
		s.p.OnFailed(v)
	}
}

// --- link store: create / status / cancel ---

// CreateParams describe a link transfer to mint.
type CreateParams struct {
	SessionID string
	Direction string
	Path      string
	// MaxBytes caps the transfer (0 → transfer.maxTransferBytes).
	MaxBytes int64
	// SHA256 is the expected digest (upload only, optional).
	SHA256    string
	Overwrite bool
	// Mode is the final permission bits (upload only, optional).
	Mode *os.FileMode
}

// Created is the result of minting a link.
type Created struct {
	TransferID string
	URL        string
	Method     string
	ExpiresAt  time.Time
	MaxBytes   int64
	Command    string
}

// Create mints a single-use transfer link bound to (account, client, session,
// direction, path, byte cap, expected digest). The caller has already
// verified session ownership; an unknown or foreign session still answers the
// uniform "session not found".
func (s *Service) Create(ctx context.Context, c Caller, p CreateParams) (*Created, error) {
	sess, err := s.openSession(c, p.SessionID)
	if err != nil {
		return nil, err
	}
	if p.Direction != DirectionUpload && p.Direction != DirectionDownload {
		return nil, errors.New(`direction must be "upload" or "download"`)
	}
	if err := validatePath(p.Path); err != nil {
		return nil, err
	}
	maxBytes := p.MaxBytes
	switch {
	case maxBytes < 0:
		return nil, errors.New("maxBytes must be positive")
	case maxBytes == 0:
		maxBytes = s.lim.MaxTransferBytes
	case maxBytes > s.lim.MaxTransferBytes:
		return nil, fmt.Errorf("maxBytes exceeds transfer.maxTransferBytes (%d)", s.lim.MaxTransferBytes)
	}
	expect := strings.ToLower(strings.TrimSpace(p.SHA256))
	if p.Direction == DirectionDownload && (expect != "" || p.Mode != nil || p.Overwrite) {
		return nil, errors.New("sha256, overwrite and mode apply to uploads only")
	}
	if expect != "" {
		if raw, err := hex.DecodeString(expect); err != nil || len(raw) != 32 {
			return nil, errors.New("sha256 must be 64 hex characters")
		}
	}

	// Remote pre-checks through the session's shared SFTP channel: fast,
	// explicit feedback for the agent instead of a failed curl. They are
	// advisory — the claim repeats them and the commit is authoritative.
	total := int64(-1)
	err = s.inline(ctx, p.SessionID, func(client *sftp.Client) error {
		if p.Direction == DirectionUpload {
			if err := requireUploadExtensions(client); err != nil {
				return err
			}
			_, err := checkWriteDestination(client, p.Path)
			return err
		}
		fi, err := client.Stat(p.Path)
		if err != nil {
			return remoteErr("stat", p.Path, err)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s is a %s, not a regular file", p.Path, fileType(fi.Mode()))
		}
		if fi.Size() > maxBytes {
			return fmt.Errorf("%s is %d bytes, above the %d byte cap", p.Path, fi.Size(), maxBytes)
		}
		total = fi.Size()
		return nil
	})
	if err != nil {
		return nil, err
	}

	now := s.clk.Now()
	x := &xfer{
		View: View{
			TransferID: newTransferID(), AccountID: c.AccountID, SessionID: sess.SessionID,
			EndpointID: sess.EndpointID, Tier: TierLink, Direction: p.Direction, Path: p.Path,
			Status: StatePending, TotalBytes: total,
			ClientID: c.ClientID, ClientName: c.ClientName, ClientVersion: c.ClientVersion, SourceIP: c.SourceIP,
			CreatedAt: now, UpdatedAt: now,
			ExpiresAt: now.Add(time.Duration(s.lim.LinkTtlSeconds) * time.Second),
		},
		token: newToken(), maxBytes: maxBytes, expectSHA: expect, overwrite: p.Overwrite, mode: p.Mode,
	}

	s.mu.Lock()
	pendingSession, pendingGlobal := 0, 0
	for _, o := range s.byID {
		if o.Status == StatePending {
			pendingGlobal++
			if o.SessionID == p.SessionID {
				pendingSession++
			}
		}
	}
	switch {
	case pendingSession >= s.lim.MaxPendingPerSession:
		s.mu.Unlock()
		return nil, fmt.Errorf("too many unused transfer links for this session (transfer.maxPendingPerSession = %d); use or cancel one first", s.lim.MaxPendingPerSession)
	case pendingGlobal >= s.lim.MaxPendingGlobal:
		s.mu.Unlock()
		return nil, fmt.Errorf("too many unused transfer links on this server (transfer.maxPendingGlobal = %d); retry later", s.lim.MaxPendingGlobal)
	}
	if !s.makeRoomLocked() {
		s.mu.Unlock()
		return nil, fmt.Errorf("transfer status store is full (transfer.maxStatusRecords = %d); retry later", s.lim.MaxStatusRecords)
	}
	s.byID[x.TransferID] = x
	s.byToken[x.token] = x
	created := x.View
	s.mu.Unlock()

	logTransfer(created)
	s.emit(x, true)

	url := strings.TrimRight(s.p.ExternalURL(), "/") + "/api/transfers/" + x.token
	method, command := "PUT", "curl -fsS -T "+shellQuote("./"+baseName(p.Path))+" "+shellQuote(url)
	if p.Direction == DirectionDownload {
		method, command = "GET", "curl -fsS -o "+shellQuote("./"+baseName(p.Path))+" "+shellQuote(url)
	}
	return &Created{
		TransferID: x.TransferID, URL: url, Method: method, ExpiresAt: x.ExpiresAt,
		MaxBytes: maxBytes, Command: command,
	}, nil
}

// logTransfer records a transfer state change: link created (pending),
// claimed (active), and every terminal state. Never the link token.
func logTransfer(v View) {
	attrs := []any{"transfer", v.TransferID, "tier", v.Tier, "direction", v.Direction, "status", v.Status,
		"session", v.SessionID, "account", v.AccountID, "path", v.Path}
	if v.Status.finished() {
		attrs = append(attrs, "bytes", v.Bytes, "duration", v.FinishedAt.Sub(v.CreatedAt).Round(time.Millisecond))
	}
	if v.Error != "" {
		attrs = append(attrs, "err", v.Error)
	}
	level := slog.LevelInfo
	if v.Status == StateFailed {
		level = slog.LevelWarn
	}
	slog.Log(context.Background(), level, "transfer: "+string(v.Status), attrs...)
}

// makeRoomLocked keeps the status map under maxStatusRecords by evicting the
// oldest finished record; false when every record is unfinished.
func (s *Service) makeRoomLocked() bool {
	for len(s.byID) >= s.lim.MaxStatusRecords {
		var oldest *xfer
		for _, o := range s.byID {
			if o.Status.finished() && (oldest == nil || o.FinishedAt.Before(oldest.FinishedAt)) {
				oldest = o
			}
		}
		if oldest == nil {
			return false
		}
		delete(s.byID, oldest.TransferID)
	}
	return true
}

// ErrNotFound is the uniform answer for an unknown or foreign transfer id.
func errTransferNotFound(id string) error { return fmt.Errorf("transfer not found: %s", id) }

// Status reports a transfer's state: from memory while the record is
// retained, from the audit row after eviction. Ownership is (account, OAuth
// client), like sessions.
func (s *Service) Status(ctx context.Context, c Caller, transferID string) (View, error) {
	s.mu.Lock()
	x, ok := s.byID[transferID]
	var v View
	if ok {
		v = x.View
	}
	s.mu.Unlock()
	if ok {
		if v.AccountID != c.AccountID || v.ClientID != c.ClientID {
			return View{}, errTransferNotFound(transferID)
		}
		return v, nil
	}
	if s.audit == nil {
		return View{}, errTransferNotFound(transferID)
	}
	row, err := s.audit.Get(ctx, c.AccountID, transferID)
	if err != nil {
		return View{}, err
	}
	if row == nil || row.ClientID == nil || *row.ClientID != c.ClientID {
		return View{}, errTransferNotFound(transferID)
	}
	return viewFromRow(row), nil
}

// Cancel cancels a pending or active transfer and returns promptly — staging
// cleanup settles in the background and shows up in a later status. A
// transfer that is already committing is not cancellable: the call returns
// its current state and the outcome is whatever the commit reports.
func (s *Service) Cancel(ctx context.Context, c Caller, transferID string) (View, error) {
	s.mu.Lock()
	x, ok := s.byID[transferID]
	owned := ok && x.AccountID == c.AccountID && x.ClientID == c.ClientID
	s.mu.Unlock()
	if ok && !owned {
		return View{}, errTransferNotFound(transferID)
	}
	if ok {
		s.abort(x, StateCancelled, "cancelled by the client")
		return s.view(x), nil
	}
	return s.Status(ctx, c, transferID)
}

// --- helpers ---

// openSession resolves an OPEN session of the caller's account. Anything else
// about ownership (the OAuth client) was checked by the caller.
func (s *Service) openSession(c Caller, sessionID string) (*terminal.Session, error) {
	sess := s.mgr.GetSession(sessionID)
	if sess == nil || sess.AccountID != c.AccountID {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	if sess.Status != terminal.StatusOpen {
		return nil, fmt.Errorf("session %s is not open (status: %s)", sessionID, sess.Status)
	}
	return sess, nil
}

func validatePath(p string) error {
	if p == "" {
		return errors.New("path is required")
	}
	if !strings.HasPrefix(p, "/") {
		return errors.New("path must be absolute; the file tools do not follow the shell's working directory")
	}
	if strings.ContainsRune(p, 0) {
		return errors.New("path must not contain NUL")
	}
	return nil
}

func requireUploadExtensions(client *sftp.Client) error {
	_, rename := client.HasExtension(extPosixRename)
	_, link := client.HasExtension(extHardlink)
	if !rename || !link {
		return errors.New("remote SFTP server lacks posix-rename/hardlink extensions; use shellwatch_write_file or the PTY")
	}
	return nil
}

// checkWriteDestination is the best-effort pre-check shared by both write
// tiers: a symlink or a special file is refused; a regular file's info is
// returned (nil when the destination does not exist).
func checkWriteDestination(client *sftp.Client, dest string) (os.FileInfo, error) {
	fi, err := client.Lstat(dest)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, remoteErr("lstat", dest, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("destination is a symlink; write to its target explicitly")
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("destination is a %s, not a regular file", fileType(fi.Mode()))
	}
	return fi, nil
}

func fileType(m os.FileMode) string {
	switch {
	case m.IsRegular():
		return "file"
	case m.IsDir():
		return "directory"
	case m&os.ModeSymlink != 0:
		return "symlink"
	case m&os.ModeNamedPipe != 0:
		return "fifo"
	case m&os.ModeSocket != 0:
		return "socket"
	case m&os.ModeDevice != 0:
		return "device"
	}
	return "other"
}

func remoteErr(op, path string, err error) error {
	return fmt.Errorf("%s %s: %w", op, path, err)
}

// isConnLost reports an SFTP failure caused by the channel or connection
// going away rather than by an answer from the server.
func isConnLost(err error) bool {
	return errors.Is(err, sftp.ErrSSHFxConnectionLost) || errors.Is(err, os.ErrClosed)
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	if p == "" {
		return "file"
	}
	return p
}

// shellQuote single-quotes s for the curl hint (POSIX shells).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newTransferID() string { return "xfer_" + randHex(8) }

// newToken returns an opaque 32-byte random credential (base64url).
func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
