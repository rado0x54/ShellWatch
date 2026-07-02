// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Audit writers (port of session-lifecycle-writer.ts + signing-requests-writer.ts).
// They subscribe to the terminal manager's guaranteed status hooks and the
// approval store's created/resolved events, denormalizing a snapshot at write
// time so history never rewrites. Failures are logged, never fatal (audit must
// not break a session or a sign).
package audit

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// Writer persists lifecycle + signing audit records.
type Writer struct {
	db  *sql.DB
	clk clock.Clock
}

func NewWriter(db *sql.DB, clk clock.Clock) *Writer {
	if clk == nil {
		clk = clock.Real{}
	}
	return &Writer{db: db, clk: clk}
}

const isoMillis = "2006-01-02T15:04:05.000Z"

// AttachManager subscribes to session status transitions: INSERT on
// opening->open, UPDATE (idempotent on closed_at) on ->closed/->error.
func (w *Writer) AttachManager(m *terminal.Manager, snapshot func(sessionID string) *terminal.Session) {
	m.SubscribeStatus(func(e terminal.StatusEvent) {
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
		case terminal.StatusClosed, terminal.StatusError:
			w.recordClose(e)
		}
	})
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
		`UPDATE audit_session_lifecycle SET status = ?, closed_at = ?, close_reason = ?
		 WHERE session_id = ? AND closed_at IS NULL`,
		string(e.Status), now.Format(isoMillis), nz(string(e.Reason)), e.SessionID)
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
	_, err := w.db.Exec(
		`INSERT INTO audit_signing_requests (id, account_id, type, source, created_at,
			source_ip, endpoint_label, endpoint_address, session_id,
			mcp_reason, mcp_client_name, mcp_client_version, client_hostname, client_os, client_version,
			credential_id, passkey_label, user_verification, key_label, key_fingerprint)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.AccountID, string(a.Type), a.Context.Source, a.CreatedAt.UTC().Format(isoMillis),
		nz(a.Context.SourceIP), nz(a.Context.EndpointLabel), nz(a.Context.EndpointAddress), nz(a.Context.SessionID),
		nz(a.Context.MCPReason), nz(a.Context.MCPClientName), nz(a.Context.MCPClientVer),
		nz(a.Context.ClientHostname), nz(a.Context.ClientOS), nz(a.Context.ClientVersion),
		nz(a.CredentialID), nz(a.PasskeyLabel), nz(a.UserVerification), nz(a.KeyLabel), nz(a.KeyFingerprint))
	if err != nil {
		slog.Warn("audit: insert signing-created failed", "action", a.ID, "err", err)
	}
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

var _ = context.Background
