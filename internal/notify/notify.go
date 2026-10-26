// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package notify is the account notification log (#252): server-originated
// events the user must not miss, kept as an append-only audit surface (the
// Notifications tab under Audit, GET /api/audit/notifications). Publish
// persists the notification first (the durable record a reconnecting client
// re-reads) and then pushes it to every connected tab as a 'notification:new'
// WebSocket message. Toast rendering, dedupe, and per-type action links all
// key off the notification id and type on the client — never off message
// text.
package notify

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/ids"
)

const (
	pageLimitDefault = 50
	pageLimitMax     = 500 // matches the audit readers' clampLimit
)

// Severity levels (CHECK-constrained in the notifications table).
const (
	SeverityInfo    = "info"
	SeverityWarning = "warning"
	SeverityError   = "error"
)

// TypeHostKeyMismatch is a dial refused before authentication because the
// server presented a key that differs from the pin (#241). Payload:
// {endpointId, endpointLabel, endpointAddress, keyType, observedFingerprint,
// pinnedFingerprint, auditId}.
const TypeHostKeyMismatch = "host-key-mismatch"

// TypeSessionConnectFailed is any other failed SSH connect, whatever the
// trigger (UI click or MCP agent) — the agent-triggered ones have no other
// human-visible surface. Payload: {endpointId, endpointLabel,
// endpointAddress, trigger, mcpClientName, mcpClientVersion, mcpReason,
// sourceIp, error}.
const TypeSessionConnectFailed = "session-connect-failed"

// Notification is the wire/domain shape of one notification row.
type Notification struct {
	ID        string         `json:"id"`
	AccountID string         `json:"accountId"`
	Type      string         `json:"type"`
	Severity  string         `json:"severity"`
	Title     string         `json:"title"`
	Detail    *string        `json:"detail"`
	Payload   map[string]any `json:"payload"`
	CreatedAt string         `json:"createdAt"`
}

// Broadcaster pushes a message to every connected tab of an account
// (satisfied by *ws.Hub; nil skips the push — tests, early boot).
type Broadcaster interface {
	SendToAccount(accountID string, msg any)
}

// Service owns the notifications table and the WS fan-out.
type Service struct {
	db  *sql.DB
	clk clock.Clock
	// NewID mints notification ids (ids.NewUUID when nil).
	NewID func() string
	// Hub receives the 'notification:new' push; may be nil.
	Hub Broadcaster
}

func NewService(db *sql.DB, clk clock.Clock) *Service {
	if clk == nil {
		clk = clock.Real{}
	}
	return &Service{db: db, clk: clk}
}

// PublishParams describe one notification to record and push.
type PublishParams struct {
	AccountID string
	Type      string
	Severity  string
	Title     string
	// Detail is the long-form text behind the toast's "Details" view.
	Detail string
	// Payload is the type-specific structured data (action links on the
	// client are derived from Type + Payload, never from text).
	Payload map[string]any
}

// Publish persists the notification and pushes it to the account's tabs.
// Returns the stored notification; the id lets the HTTP error path that
// raced the same event reference it ("" id on a failed insert — callers
// degrade to their plain error).
func (s *Service) Publish(ctx context.Context, p PublishParams) Notification {
	newID := s.NewID
	if newID == nil {
		newID = ids.NewUUID
	}
	n := Notification{
		ID: newID(), AccountID: p.AccountID, Type: p.Type, Severity: p.Severity,
		Title: p.Title, Payload: p.Payload,
		CreatedAt: s.clk.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
	if p.Detail != "" {
		d := p.Detail
		n.Detail = &d
	}
	var payload sql.NullString
	if p.Payload != nil {
		raw, err := json.Marshal(p.Payload)
		if err != nil {
			slog.Warn("notify: payload marshal failed", "type", p.Type, "err", err)
		} else {
			payload = sql.NullString{String: string(raw), Valid: true}
		}
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO notifications (id, account_id, type, severity, title, detail, payload, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		n.ID, n.AccountID, n.Type, n.Severity, n.Title, nullable(p.Detail), payload, n.CreatedAt); err != nil {
		slog.Warn("notify: insert failed", "type", p.Type, "err", err)
		n.ID = "" // not persisted: nothing to reference
	}
	if s.Hub != nil {
		s.Hub.SendToAccount(p.AccountID, map[string]any{"type": "notification:new", "notification": n})
	}
	return n
}

// Page is a keyset-paginated result ({rows, nextCursor}).
type Page struct {
	Rows       []Notification `json:"rows"`
	NextCursor *string        `json:"nextCursor"`
}

type cursor struct {
	CreatedAt string `json:"createdAt"`
	ID        string `json:"id"`
}

// List returns an account-scoped, keyset-paginated page ordered by
// (created_at, id) DESC — same scheme as the audit readers.
func (s *Service) List(ctx context.Context, accountID, cursorStr string, limit int) (Page, error) {
	if limit <= 0 {
		limit = pageLimitDefault
	}
	if limit > pageLimitMax {
		limit = pageLimitMax
	}
	conds := []string{"account_id = ?"}
	args := []any{accountID}
	if c := decodeCursor(cursorStr); c != nil {
		conds = append(conds, "(created_at < ? OR (created_at = ? AND id < ?))")
		args = append(args, c.CreatedAt, c.CreatedAt, c.ID)
	}
	query := `SELECT id, account_id, type, severity, title, detail, payload, created_at
		FROM notifications WHERE ` + strings.Join(conds, " AND ") +
		` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit+1)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return Page{}, err
	}
	defer rows.Close()
	out := []Notification{} // non-nil: empty pages serialize as "rows": []
	for rows.Next() {
		var n Notification
		var detail, payload sql.NullString
		if err := rows.Scan(&n.ID, &n.AccountID, &n.Type, &n.Severity, &n.Title, &detail, &payload, &n.CreatedAt); err != nil {
			return Page{}, err
		}
		if detail.Valid {
			d := detail.String
			n.Detail = &d
		}
		if payload.Valid {
			if err := json.Unmarshal([]byte(payload.String), &n.Payload); err != nil {
				slog.Warn("notify: stored payload unmarshal failed", "id", n.ID, "err", err)
			}
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return Page{}, err
	}
	var next *string
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		raw, _ := json.Marshal(cursor{CreatedAt: last.CreatedAt, ID: last.ID})
		c := base64.RawURLEncoding.EncodeToString(raw)
		next = &c
	}
	return Page{Rows: out, NextCursor: next}, nil
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

func nullable(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
