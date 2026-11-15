// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// File-transfer audit log (#263) — the fifth audit surface: one row per MCP
// file operation (inline list/read/write, and out-of-band link transfers).
// Account-scoped. A link transfer's row is saved AHEAD of each state
// transition, so the in-memory transfer store can answer `status` from it
// after eviction and a crash leaves a truthful record (see migration 00005).
package audit

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"

	"github.com/rado0x54/shellwatch/internal/clock"
)

// File-transfer statuses that are not terminal: a row still in one of these
// at startup was interrupted by a restart.
const (
	FileTransferPending    = "pending"
	FileTransferActive     = "active"
	FileTransferCommitting = "committing"
	FileTransferFailed     = "failed"
)

// FileTransferRow is the wire/domain shape of one file_transfers row.
type FileTransferRow struct {
	TransferID string `json:"transferId"`
	AccountID  string `json:"accountId"`
	SessionID  string `json:"sessionId"`
	EndpointID string `json:"endpointId"`
	// Tier is "inline" or "link"; Direction is "upload", "download" or "list".
	Tier      string `json:"tier"`
	Direction string `json:"direction"`
	Path      string `json:"path"`
	Status    string `json:"status"`
	Bytes     int64  `json:"bytes"`
	// TotalBytes is the expected size when known (downloads; uploads that
	// announced a Content-Length).
	TotalBytes    *int64  `json:"totalBytes"`
	SHA256        *string `json:"sha256"`
	Error         *string `json:"error"`
	Truncated     *bool   `json:"truncated"`
	CommitOutcome *string `json:"commitOutcome"`
	Cleanup       *string `json:"cleanup"`
	StagingPath   *string `json:"stagingPath"`
	// ClientID is the authenticated OAuth client_id; the MCP name/version are
	// client-reported.
	ClientID         *string `json:"clientId"`
	MCPClientName    *string `json:"mcpClientName"`
	MCPClientVersion *string `json:"mcpClientVersion"`
	SourceIP         *string `json:"sourceIp"`
	CreatedAt        string  `json:"createdAt"`
	UpdatedAt        string  `json:"updatedAt"`
	FinishedAt       *string `json:"finishedAt"`
}

// FileTransfers owns the file_transfers table.
type FileTransfers struct {
	db  *sql.DB
	clk clock.Clock
}

func NewFileTransfers(db *sql.DB, clk clock.Clock) *FileTransfers {
	if clk == nil {
		clk = clock.Real{}
	}
	return &FileTransfers{db: db, clk: clk}
}

const fileTransferColumns = `id, account_id, session_id, endpoint_id, tier, direction, path, status,
	bytes, total_bytes, sha256, error, truncated, commit_outcome, cleanup, staging_path,
	client_id, mcp_client_name, mcp_client_version, source_ip, created_at, updated_at, finished_at`

// Save upserts the row: the first call inserts it, later calls overwrite the
// mutable outcome columns. Identity columns (account, session, path, ...) are
// written once and never rewritten. Failures are logged, never returned — an
// audit write must not break a transfer (same rule as the other writers).
func (f *FileTransfers) Save(r FileTransferRow) {
	if r.UpdatedAt == "" {
		r.UpdatedAt = f.clk.Now().UTC().Format(isoMillis)
	}
	if r.CreatedAt == "" {
		r.CreatedAt = r.UpdatedAt
	}
	_, err := f.db.Exec(
		`INSERT INTO file_transfers (`+fileTransferColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
			status = excluded.status, bytes = excluded.bytes, total_bytes = excluded.total_bytes,
			sha256 = excluded.sha256, error = excluded.error, truncated = excluded.truncated,
			commit_outcome = excluded.commit_outcome, cleanup = excluded.cleanup,
			staging_path = excluded.staging_path, updated_at = excluded.updated_at,
			finished_at = excluded.finished_at`,
		r.TransferID, r.AccountID, r.SessionID, r.EndpointID, r.Tier, r.Direction, r.Path, r.Status,
		r.Bytes, nullInt(r.TotalBytes), nullStr(r.SHA256), nullStr(r.Error), nullBool(r.Truncated),
		nullStr(r.CommitOutcome), nullStr(r.Cleanup), nullStr(r.StagingPath),
		nullStr(r.ClientID), nullStr(r.MCPClientName), nullStr(r.MCPClientVersion), nullStr(r.SourceIP),
		r.CreatedAt, r.UpdatedAt, nullStr(r.FinishedAt))
	if err != nil {
		slog.Warn("audit: save file-transfer failed", "transfer", r.TransferID, "status", r.Status, "err", err)
	}
}

// FileTransferFilters narrow a file-transfer page. All fields are optional.
type FileTransferFilters struct {
	SessionID string
	Direction string
	Status    string
	Tier      string
	// Cursor is the opaque keyset cursor of the previous page; Limit the page
	// size (clamped like the other audit readers).
	Cursor string
	Limit  int
}

// List returns an account-scoped, keyset-paginated page ordered by
// (created_at, id) DESC.
func (f *FileTransfers) List(ctx context.Context, accountID string, flt FileTransferFilters) (Page[FileTransferRow], error) {
	limit := clampLimit(flt.Limit)
	conds := []string{"account_id = ?"}
	args := []any{accountID}
	for col, v := range map[string]string{
		"session_id": flt.SessionID, "direction": flt.Direction, "status": flt.Status, "tier": flt.Tier,
	} {
		if v != "" {
			conds = append(conds, col+" = ?")
			args = append(args, v)
		}
	}
	if c := decodeCursor(flt.Cursor); c != nil {
		conds = append(conds, "(created_at < ? OR (created_at = ? AND id < ?))")
		args = append(args, c.CreatedAt, c.CreatedAt, c.ID)
	}
	rows, err := f.db.QueryContext(ctx,
		`SELECT `+fileTransferColumns+` FROM file_transfers WHERE `+strings.Join(conds, " AND ")+
			` ORDER BY created_at DESC, id DESC LIMIT ?`, append(args, limit+1)...)
	if err != nil {
		return Page[FileTransferRow]{}, err
	}
	defer rows.Close()
	out := []FileTransferRow{} // non-nil: empty pages serialize as "rows": []
	for rows.Next() {
		r, err := scanFileTransfer(rows)
		if err != nil {
			return Page[FileTransferRow]{}, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return Page[FileTransferRow]{}, err
	}
	next := paginate(&out, limit, func(r FileTransferRow) any {
		return cursor{CreatedAt: r.CreatedAt, ID: r.TransferID}
	})
	return Page[FileTransferRow]{Rows: out, NextCursor: next}, nil
}

// Get returns one account-scoped row, or nil when absent.
func (f *FileTransfers) Get(ctx context.Context, accountID, transferID string) (*FileTransferRow, error) {
	row := f.db.QueryRowContext(ctx,
		`SELECT `+fileTransferColumns+` FROM file_transfers WHERE account_id = ? AND id = ?`,
		accountID, transferID)
	r, err := scanFileTransfer(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ReconcileInterrupted is the startup reconciliation: tokens and live
// transfers do not survive a restart, so every row still unfinished is closed
// out truthfully. pending/active rows become failed ("server restarted", and
// cleanup failed when a staging directory was recorded); committing rows
// become failed with commitOutcome "unknown", since the commit may have been
// issued. A finished upload (completed or failed) that still records a
// staging path but no cleanup result was interrupted between persisting its
// outcome and removing its staging directory (#287): it keeps its status,
// commit outcome and error, and only gets cleanup failed. Staging paths are
// preserved. Returns the rows as they now read, so the caller can notify each
// account once.
func (f *FileTransfers) ReconcileInterrupted(ctx context.Context) ([]FileTransferRow, error) {
	rows, err := f.db.QueryContext(ctx,
		`SELECT `+fileTransferColumns+` FROM file_transfers
		 WHERE status IN (?, ?, ?) OR (staging_path IS NOT NULL AND cleanup IS NULL)
		 ORDER BY created_at, id`,
		FileTransferPending, FileTransferActive, FileTransferCommitting)
	if err != nil {
		return nil, err
	}
	var interrupted []FileTransferRow
	for rows.Next() {
		r, err := scanFileTransfer(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		interrupted = append(interrupted, r)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	now := f.clk.Now().UTC().Format(isoMillis)
	for i := range interrupted {
		r := &interrupted[i]
		if r.StagingPath != nil {
			failed := "failed"
			r.Cleanup = &failed
		}
		r.UpdatedAt = now
		switch r.Status {
		case FileTransferPending, FileTransferActive, FileTransferCommitting:
			msg := "server restarted"
			if r.Status == FileTransferCommitting {
				unknown := "unknown"
				r.CommitOutcome = &unknown
				msg = "server restarted during commit; the commit outcome is unknown — inspect the destination (size, sha256) before retrying"
			}
			r.Status = FileTransferFailed
			r.Error = &msg
			r.FinishedAt = &now
		default:
			// Already finished: the outcome is known, only the staging
			// cleanup never ran.
			if r.FinishedAt == nil {
				r.FinishedAt = &now
			}
		}
		f.Save(*r)
	}
	return interrupted, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanFileTransfer(s rowScanner) (FileTransferRow, error) {
	var r FileTransferRow
	var total sql.NullInt64
	var truncated sql.NullBool
	var sha, errMsg, commit, cleanup, staging, clientID, mcpName, mcpVer, ip, finished sql.NullString
	if err := s.Scan(&r.TransferID, &r.AccountID, &r.SessionID, &r.EndpointID, &r.Tier, &r.Direction,
		&r.Path, &r.Status, &r.Bytes, &total, &sha, &errMsg, &truncated, &commit, &cleanup, &staging,
		&clientID, &mcpName, &mcpVer, &ip, &r.CreatedAt, &r.UpdatedAt, &finished); err != nil {
		return r, err
	}
	r.TotalBytes = ni(total)
	r.SHA256 = ns(sha)
	r.Error = ns(errMsg)
	if truncated.Valid {
		r.Truncated = &truncated.Bool
	}
	r.CommitOutcome = ns(commit)
	r.Cleanup = ns(cleanup)
	r.StagingPath = ns(staging)
	r.ClientID = ns(clientID)
	r.MCPClientName = ns(mcpName)
	r.MCPClientVersion = ns(mcpVer)
	r.SourceIP = ns(ip)
	r.FinishedAt = ns(finished)
	return r, nil
}

func nullStr(p *string) sql.NullString {
	if p == nil || *p == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: *p, Valid: true}
}

func nullInt(p *int64) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *p, Valid: true}
}

func nullBool(p *bool) sql.NullBool {
	if p == nil {
		return sql.NullBool{}
	}
	return sql.NullBool{Bool: *p, Valid: true}
}
