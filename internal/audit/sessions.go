// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package audit is the tamper-evident session-lifecycle + signing-request
// audit log (port of src/audit/). Readers are keyset-paginated over the
// composite (account_id, created_at, id) indexes; writers subscribe to the
// terminal manager + approval broker and never join live tables at read time,
// so a passkey rename or endpoint relabel never rewrites history.
package audit

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"strings"
)

const (
	pageLimitDefault = 50
	pageLimitMax     = 200
)

// SessionRow is one session-lifecycle audit record (audit_session_lifecycle).
type SessionRow struct {
	SessionID        string  `json:"sessionId"`
	AccountID        string  `json:"accountId"`
	EndpointID       string  `json:"endpointId"`
	Source           string  `json:"source"`
	Status           string  `json:"status"`
	CreatedAt        string  `json:"createdAt"`
	ClosedAt         *string `json:"closedAt"`
	DurationMs       *int64  `json:"durationMs"`
	SourceIP         *string `json:"sourceIp"`
	MCPReason        *string `json:"mcpReason"`
	MCPClientName    *string `json:"mcpClientName"`
	MCPClientVersion *string `json:"mcpClientVersion"`
	ClientHostname   *string `json:"clientHostname"`
	ClientOS         *string `json:"clientOs"`
	ClientVersion    *string `json:"clientVersion"`
	CloseReason      *string `json:"closeReason"`
}

// SessionFilters narrow a session-lifecycle page.
type SessionFilters struct {
	EndpointID string
	From       string
	To         string
}

// Page is a keyset-paginated result ({rows, nextCursor}).
type Page[T any] struct {
	Rows       []T     `json:"rows"`
	NextCursor *string `json:"nextCursor"`
}

// Sessions reads the session-lifecycle audit table.
type Sessions struct {
	db *sql.DB
}

func NewSessions(db *sql.DB) *Sessions { return &Sessions{db: db} }

// List returns an account-scoped, keyset-paginated page ordered by
// (created_at, session_id) DESC.
func (s *Sessions) List(ctx context.Context, accountID string, f SessionFilters, cursorStr string, limit int) (Page[SessionRow], error) {
	limit = clampLimit(limit)
	conds := []string{"account_id = ?"}
	args := []any{accountID}
	if f.EndpointID != "" {
		conds = append(conds, "endpoint_id = ?")
		args = append(args, f.EndpointID)
	}
	if f.From != "" {
		conds = append(conds, "created_at >= ?")
		args = append(args, f.From)
	}
	if f.To != "" {
		conds = append(conds, "created_at <= ?")
		args = append(args, f.To)
	}
	if c := decodeCursor(cursorStr); c != nil {
		conds = append(conds, "(created_at < ? OR (created_at = ? AND session_id < ?))")
		args = append(args, c.CreatedAt, c.CreatedAt, c.ID)
	}

	query := `SELECT session_id, account_id, endpoint_id, source, status, created_at,
		closed_at, duration_ms, source_ip, mcp_reason, mcp_client_name, mcp_client_version,
		client_hostname, client_os, client_version, close_reason
		FROM audit_session_lifecycle WHERE ` + strings.Join(conds, " AND ") +
		` ORDER BY created_at DESC, session_id DESC LIMIT ?`
	args = append(args, limit+1)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return Page[SessionRow]{}, err
	}
	defer rows.Close()

	var out []SessionRow
	for rows.Next() {
		var r SessionRow
		var closedAt, sourceIP, mcpReason, mcpName, mcpVer, cHost, cOS, cVer, closeReason sql.NullString
		var duration sql.NullInt64
		if err := rows.Scan(&r.SessionID, &r.AccountID, &r.EndpointID, &r.Source, &r.Status, &r.CreatedAt,
			&closedAt, &duration, &sourceIP, &mcpReason, &mcpName, &mcpVer,
			&cHost, &cOS, &cVer, &closeReason); err != nil {
			return Page[SessionRow]{}, err
		}
		r.ClosedAt = ns(closedAt)
		r.DurationMs = ni(duration)
		r.SourceIP = ns(sourceIP)
		r.MCPReason = ns(mcpReason)
		r.MCPClientName = ns(mcpName)
		r.MCPClientVersion = ns(mcpVer)
		r.ClientHostname = ns(cHost)
		r.ClientOS = ns(cOS)
		r.ClientVersion = ns(cVer)
		r.CloseReason = ns(closeReason)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return Page[SessionRow]{}, err
	}

	next := paginate(&out, limit, func(r SessionRow) cursor { return cursor{CreatedAt: r.CreatedAt, ID: r.SessionID} })
	return Page[SessionRow]{Rows: out, NextCursor: next}, nil
}

// --- cursor + helpers ---

type cursor struct {
	CreatedAt string `json:"createdAt"`
	ID        string `json:"id"`
}

func clampLimit(n int) int {
	if n <= 0 {
		return pageLimitDefault
	}
	if n > pageLimitMax {
		return pageLimitMax
	}
	return n
}

func encodeCursor(c cursor) string {
	raw, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeCursor(raw string) *cursor {
	if raw == "" {
		return nil
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil
	}
	var c cursor
	if json.Unmarshal(data, &c) != nil || c.CreatedAt == "" || c.ID == "" {
		return nil
	}
	return &c
}

// paginate trims an over-fetched slice to limit and returns the next cursor.
func paginate[T any](rows *[]T, limit int, key func(T) cursor) *string {
	if len(*rows) <= limit {
		return nil
	}
	*rows = (*rows)[:limit]
	last := (*rows)[len(*rows)-1]
	c := encodeCursor(key(last))
	return &c
}

func ns(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	return &v.String
}

func ni(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	return &v.Int64
}
