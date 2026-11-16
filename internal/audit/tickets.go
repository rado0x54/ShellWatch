// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Ticket event log (#306): one row per lifecycle event of a one-time access
// ticket and its guest session — minted, redeemed, attached, attempt-failed,
// retried, admitted, detached, reattached, ended (with the end reason),
// revoked, expired, invalidated. Account-scoped and append-only like the
// other audit tables; read through GET /api/audit/tickets. Neither the
// ticket token nor the guest cookie is ever written here.
package audit

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
)

// Ticket event names (the `event` column).
const (
	TicketMinted        = "minted"
	TicketRedeemed      = "redeemed"
	TicketAttached      = "attached"
	TicketAttemptFailed = "attempt-failed"
	TicketRetried       = "retried"
	TicketAdmitted      = "admitted"
	TicketDetached      = "detached"
	TicketReattached    = "reattached"
	TicketEnded         = "ended"
	TicketRevoked       = "revoked"
	TicketExpired       = "expired"
	TicketInvalidated   = "invalidated"
)

// TicketEventValues are the accepted `event` filter values.
var TicketEventValues = map[string]bool{
	TicketMinted: true, TicketRedeemed: true, TicketAttached: true, TicketAttemptFailed: true,
	TicketRetried: true, TicketAdmitted: true, TicketDetached: true, TicketReattached: true,
	TicketEnded: true, TicketRevoked: true, TicketExpired: true, TicketInvalidated: true,
}

// TicketEvent is one row to record. The option fields snapshot the ticket.
type TicketEvent struct {
	AccountID        string
	TicketID         string
	Event            string
	EndpointID       string
	TicketLabel      string
	Channel          string
	RedeemTTLSeconds int
	LifetimeSeconds  int
	ReasonRequired   bool
	AgentForward     bool
	Reason           string
	SourceIP         string
	UserAgent        string
	ConfirmationCode string
	SessionID        string
	Attempt          int
	EndReason        string
	DurationMs       *int64
}

// TicketEventRow is the wire shape of one audit_ticket_events row.
type TicketEventRow struct {
	ID               string  `json:"id"`
	AccountID        string  `json:"accountId"`
	TicketID         string  `json:"ticketId"`
	Event            string  `json:"event"`
	CreatedAt        string  `json:"createdAt"`
	EndpointID       string  `json:"endpointId"`
	TicketLabel      *string `json:"ticketLabel"`
	Channel          *string `json:"channel"`
	RedeemTTLSeconds int64   `json:"redeemTtlSeconds"`
	LifetimeSeconds  int64   `json:"lifetimeSeconds"`
	ReasonRequired   bool    `json:"reasonRequired"`
	AgentForward     bool    `json:"agentForward"`
	Reason           *string `json:"reason"`
	SourceIP         *string `json:"sourceIp"`
	UserAgent        *string `json:"userAgent"`
	ConfirmationCode *string `json:"confirmationCode"`
	SessionID        *string `json:"sessionId"`
	Attempt          *int64  `json:"attempt"`
	EndReason        *string `json:"endReason"`
	DurationMs       *int64  `json:"durationMs"`
}

// TicketEvents owns the audit_ticket_events table.
type TicketEvents struct {
	db  *sql.DB
	clk clock.Clock
	// NewID mints row ids; defaults to a time-ordered UUID (v7 layout with a
	// per-millisecond counter), so events recorded in the same millisecond
	// still page in the order they happened.
	NewID func() string

	idMu    sync.Mutex
	lastMs  int64
	counter uint16
}

// orderedID returns a UUIDv7-layout id whose order follows the clock and,
// within one millisecond, the call order (12-bit counter in rand_a).
func (t *TicketEvents) orderedID(now time.Time) string {
	t.idMu.Lock()
	ms := now.UnixMilli()
	if ms <= t.lastMs {
		ms = t.lastMs
		t.counter++
		if t.counter > 0x0fff {
			ms++
			t.counter = 0
		}
	} else {
		t.counter = 0
	}
	t.lastMs = ms
	counter := t.counter
	t.idMu.Unlock()
	var b [16]byte
	_, _ = rand.Read(b[8:])
	for i := 0; i < 6; i++ {
		b[i] = byte(ms >> (40 - 8*i))
	}
	b[6] = 0x70 | byte(counter>>8)
	b[7] = byte(counter)
	b[8] = 0x80 | (b[8] & 0x3f)
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func NewTicketEvents(db *sql.DB, clk clock.Clock) *TicketEvents {
	if clk == nil {
		clk = clock.Real{}
	}
	return &TicketEvents{db: db, clk: clk}
}

// Record appends one event. Failures are logged, never returned: an audit
// write must not break a ticket flow (same rule as the other writers).
func (t *TicketEvents) Record(ev TicketEvent) {
	now := t.clk.Now()
	id := ""
	if t.NewID != nil {
		id = t.NewID()
	} else {
		id = t.orderedID(now)
	}
	var attempt sql.NullInt64
	if ev.Attempt > 0 {
		attempt = sql.NullInt64{Int64: int64(ev.Attempt), Valid: true}
	}
	var dur sql.NullInt64
	if ev.DurationMs != nil {
		dur = sql.NullInt64{Int64: *ev.DurationMs, Valid: true}
	}
	_, err := t.db.Exec(
		`INSERT INTO audit_ticket_events (`+ticketEventColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, ev.AccountID, ev.TicketID, ev.Event, now.UTC().Format(isoMillis), ev.EndpointID,
		nz(ev.TicketLabel), nz(ev.Channel), ev.RedeemTTLSeconds, ev.LifetimeSeconds,
		boolInt(ev.ReasonRequired), boolInt(ev.AgentForward),
		nz(ev.Reason), nz(ev.SourceIP), nz(ev.UserAgent), nz(ev.ConfirmationCode),
		nz(ev.SessionID), attempt, nz(ev.EndReason), dur)
	if err != nil {
		slog.Warn("audit: insert ticket event failed", "ticket", ev.TicketID, "event", ev.Event, "err", err)
	}
}

const ticketEventColumns = `id, account_id, ticket_id, event, created_at, endpoint_id, ticket_label, channel,
	redeem_ttl_seconds, lifetime_seconds, reason_required, agent_forward,
	reason, source_ip, user_agent, confirmation_code, session_id, attempt, end_reason, duration_ms`

// TicketEventFilters narrow a ticket-event page. All fields are optional.
type TicketEventFilters struct {
	TicketID string
	Event    string
	Cursor   string
	Limit    int
}

// List returns an account-scoped, keyset-paginated page ordered by
// (created_at, id) DESC.
func (t *TicketEvents) List(ctx context.Context, accountID string, f TicketEventFilters) (Page[TicketEventRow], error) {
	limit := clampLimit(f.Limit)
	conds := []string{"account_id = ?"}
	args := []any{accountID}
	if f.TicketID != "" {
		conds = append(conds, "ticket_id = ?")
		args = append(args, f.TicketID)
	}
	if f.Event != "" {
		conds = append(conds, "event = ?")
		args = append(args, f.Event)
	}
	if c := decodeCursor(f.Cursor); c != nil {
		conds = append(conds, "(created_at < ? OR (created_at = ? AND id < ?))")
		args = append(args, c.CreatedAt, c.CreatedAt, c.ID)
	}
	rows, err := t.db.QueryContext(ctx,
		`SELECT `+ticketEventColumns+` FROM audit_ticket_events WHERE `+strings.Join(conds, " AND ")+
			` ORDER BY created_at DESC, id DESC LIMIT ?`, append(args, limit+1)...)
	if err != nil {
		return Page[TicketEventRow]{}, err
	}
	defer rows.Close()
	out := []TicketEventRow{} // non-nil: empty pages serialize as "rows": []
	for rows.Next() {
		var r TicketEventRow
		var label, channel, reason, ip, ua, code, sid, endReason sql.NullString
		var attempt, dur sql.NullInt64
		var reasonReq, agentFwd int64
		if err := rows.Scan(&r.ID, &r.AccountID, &r.TicketID, &r.Event, &r.CreatedAt, &r.EndpointID,
			&label, &channel, &r.RedeemTTLSeconds, &r.LifetimeSeconds, &reasonReq, &agentFwd,
			&reason, &ip, &ua, &code, &sid, &attempt, &endReason, &dur); err != nil {
			return Page[TicketEventRow]{}, err
		}
		r.TicketLabel, r.Channel, r.Reason = ns(label), ns(channel), ns(reason)
		r.SourceIP, r.UserAgent, r.ConfirmationCode = ns(ip), ns(ua), ns(code)
		r.SessionID, r.Attempt, r.EndReason, r.DurationMs = ns(sid), ni(attempt), ns(endReason), ni(dur)
		r.ReasonRequired, r.AgentForward = reasonReq != 0, agentFwd != 0
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return Page[TicketEventRow]{}, err
	}
	next := paginate(&out, limit, func(r TicketEventRow) any { return cursor{CreatedAt: r.CreatedAt, ID: r.ID} })
	return Page[TicketEventRow]{Rows: out, NextCursor: next}, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
