// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Audit writers (port of session-lifecycle-writer.ts + signing-requests-writer.ts).
// They subscribe to the terminal manager's guaranteed status hooks and the
// approval store's created/resolved events, denormalizing a snapshot at write
// time so history never rewrites. Failures are logged, never fatal (audit must
// not break a session or a sign).
package audit

import (
	"database/sql"
	"log/slog"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/ids"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// Writer persists lifecycle + signing audit records.
type Writer struct {
	db  *sql.DB
	clk clock.Clock
	// NewID mints ids for writer-originated rows (host-key events); defaults
	// to a UUID. Actions carry their own ids.
	NewID func() string
}

func (w *Writer) newEventID() string {
	if w.NewID != nil {
		return w.NewID()
	}
	return ids.NewUUID()
}

func NewWriter(db *sql.DB, clk clock.Clock) *Writer {
	if clk == nil {
		clk = clock.Real{}
	}
	return &Writer{db: db, clk: clk}
}

const isoMillis = clock.ISOMillis

// AttachManager subscribes to session status transitions: INSERT on
// opening->open, UPDATE (idempotent on closed_at) on ->closed/->error.
func (w *Writer) AttachManager(m *terminal.Manager, snapshot func(sessionID string) *terminal.Session) {
	m.SubscribeStatus(func(e terminal.StatusEvent) {
		w.handleSessionStatus(e, snapshot)
	})
}

// handleSessionStatus is AttachManager's subscriber body (split out so the
// absorbed-open race below is unit-testable).
func (w *Writer) handleSessionStatus(e terminal.StatusEvent, snapshot func(sessionID string) *terminal.Session) {
	switch e.Status {
	case terminal.StatusOpen:
		if e.Previous != terminal.StatusOpening {
			return
		}
		s := snapshot(e.SessionID)
		if s == nil {
			return
		}
		w.insertOpen(s)
	case terminal.StatusClosing:
		// A close that raced Create (Destroy/account deletion between
		// registration and setStatus(Open)) absorbs the Open transition,
		// so the Open-keyed insert above never fires — insert here or the
		// session vanishes from the append-only log. Unreachable on the
		// normal path, where Closing's Previous is open.
		if e.Previous != terminal.StatusOpening {
			return
		}
		s := snapshot(e.SessionID)
		if s == nil {
			return
		}
		w.insertOpen(s)
	case terminal.StatusClosed, terminal.StatusError:
		w.recordClose(e)
	}
}

func (w *Writer) insertOpen(s *terminal.Session) {
	_, err := w.db.Exec(
		`INSERT INTO audit_session_lifecycle (session_id, account_id, endpoint_id, source, status, created_at, source_ip, mcp_reason, mcp_client_name, mcp_client_version)
		 VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)`,
		s.SessionID, s.AccountID, s.EndpointID, string(s.Source), s.CreatedAt.UTC().Format(isoMillis),
		nz(s.SourceIP), nz(s.MCPReason), nz(s.MCPClientName), nz(s.MCPClientVer))
	if err != nil {
		slog.Warn("audit: insert session-open failed", "session", s.SessionID, "err", err)
	}
}

func (w *Writer) recordClose(e terminal.StatusEvent) {
	now := w.clk.Now().UTC()
	// Idempotent on closed_at: a session re-traversing a terminal state must not
	// have its first-close timing rewritten.
	_, err := w.db.Exec(
		`UPDATE audit_session_lifecycle SET status = ?, closed_at = ?, duration_ms = ?, close_reason = ?
		 WHERE session_id = ? AND closed_at IS NULL`,
		string(e.Status), now.Format(isoMillis), now.Sub(e.CreatedAt.UTC()).Milliseconds(),
		nz(string(e.Reason)), e.SessionID)
	if err != nil {
		slog.Warn("audit: record session-close failed", "session", e.SessionID, "err", err)
	}
}

// AttachStore subscribes to the pending-action store: INSERT on created, UPDATE
// outcome/latency on resolved.
func (w *Writer) AttachStore(store *approval.Store) {
	store.OnCreated(func(a *approval.Action) { w.insertSigning(a) })
	store.OnResolved(func(ev approval.ResolvedEvent) { w.recordResolution(ev) })
}

func (w *Writer) insertSigning(a *approval.Action) {
	hostKeyFp := ""
	if a.Context.HostKey != nil {
		hostKeyFp = a.Context.HostKey.Fingerprint
	}
	_, err := w.db.Exec(
		`INSERT INTO audit_signing_requests (id, account_id, type, source, created_at,
			source_ip, endpoint_label, endpoint_address, session_id,
			mcp_reason, mcp_client_name, mcp_client_version, client_hostname, client_os, client_version,
			credential_id, passkey_label, user_verification, key_label, key_fingerprint, host_key_fingerprint)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.AccountID, string(a.Type), a.Context.Source, a.CreatedAt.UTC().Format(isoMillis),
		nz(a.Context.SourceIP), nz(a.Context.EndpointLabel), nz(a.Context.EndpointAddress), nz(a.Context.SessionID),
		nz(a.Context.MCPReason), nz(a.Context.MCPClientName), nz(a.Context.MCPClientVer),
		nz(a.Context.ClientHostname), nz(a.Context.ClientOS), nz(a.Context.ClientVersion),
		nz(a.CredentialID), nz(a.PasskeyLabel), nz(a.UserVerification), nz(a.KeyLabel), nz(a.KeyFingerprint),
		nz(hostKeyFp))
	if err != nil {
		slog.Warn("audit: insert signing-created failed", "action", a.ID, "err", err)
	}
}

// MarkHostKeyPinned flags the approval that pinned an endpoint's host key
// (#241) — called by the pin store right after the compare-and-set lands.
func (w *Writer) MarkHostKeyPinned(actionID string) {
	if actionID == "" {
		return
	}
	if _, err := w.db.Exec(
		`UPDATE audit_signing_requests SET host_key_pinned = 1 WHERE id = ?`, actionID); err != nil {
		slog.Warn("audit: mark host-key pinned failed", "action", actionID, "err", err)
	}
}

// HostKeyEvent is a host-key audit record (#241): a mismatch that aborted a
// handshake ('host-key-mismatch', outcome denied) or a pin removal
// ('host-key-cleared' — host/port change or a human forgetting the key).
type HostKeyEvent struct {
	Type             string // "host-key-mismatch" | "host-key-cleared"
	AccountID        string
	EndpointID       string
	EndpointLabel    string
	EndpointAddress  string
	Source           string // "endpoint-auth" (mismatch) | "endpoint-admin" (cleared)
	Fingerprint      string // observed key (mismatch) / the cleared pin
	PriorFingerprint string // the pinned key a mismatch was checked against
	Reason           string // what cleared the pin (cancel_reason column)
	SourceIP         string
	MCPReason        string
	MCPClientName    string
	MCPClientVersion string
}

// RecordHostKeyEvent writes a host-key audit row and returns its id ("" when
// the insert failed) so a notification can reference the audit record in its
// typed payload (#252). These rows are born resolved: there is no pending
// phase (a mismatch is denied automatically; a clear already happened).
func (w *Writer) RecordHostKeyEvent(ev HostKeyEvent) string {
	now := w.clk.Now().UTC().Format(isoMillis)
	id := w.newEventID()
	outcome := sql.NullString{}
	if ev.Type == "host-key-mismatch" {
		outcome = sql.NullString{String: "denied", Valid: true}
	}
	_, err := w.db.Exec(
		`INSERT INTO audit_signing_requests (id, account_id, type, source, created_at, resolved_at, outcome, latency_ms,
			source_ip, endpoint_id, endpoint_label, endpoint_address,
			mcp_reason, mcp_client_name, mcp_client_version,
			host_key_fingerprint, host_key_prior_fingerprint, cancel_reason)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, ev.AccountID, ev.Type, ev.Source, now, now, outcome,
		nz(ev.SourceIP), nz(ev.EndpointID), nz(ev.EndpointLabel), nz(ev.EndpointAddress),
		nz(ev.MCPReason), nz(ev.MCPClientName), nz(ev.MCPClientVersion),
		nz(ev.Fingerprint), nz(ev.PriorFingerprint), nz(ev.Reason))
	if err != nil {
		slog.Warn("audit: insert host-key event failed", "type", ev.Type, "endpoint", ev.EndpointID, "err", err)
		return ""
	}
	return id
}

func (w *Writer) recordResolution(ev approval.ResolvedEvent) {
	a := ev.Action
	latency := ev.ResolvedAt.Sub(a.CreatedAt).Milliseconds()
	_, err := w.db.Exec(
		`UPDATE audit_signing_requests SET resolved_at = ?, outcome = ?, latency_ms = ?, cancel_reason = ?
		 WHERE id = ? AND resolved_at IS NULL`,
		ev.ResolvedAt.UTC().Format(isoMillis), string(ev.Outcome), latency, nz(ev.CancelReason), a.ID)
	if err != nil {
		slog.Warn("audit: record signing-resolution failed", "action", a.ID, "err", err)
	}
}

func nz(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
