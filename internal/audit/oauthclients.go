// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// OAuth client registration log (#242) — the fourth audit surface, and the
// only one that is NOT account-scoped: mediated DCR and CIMD both run before
// any account is identified, so there is no subject to scope a row to (see
// migration 00004). Reads are admin-only; the route gate enforces that.
//
// This is a log, not a registry. Current client state stays in Hydra; rows
// here are a snapshot denormalized at write time, so a client deleted in Hydra
// leaves its history intact.
package audit

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

// Registration origins.
const (
	OriginDCR  = "dcr"
	OriginCIMD = "cimd"
)

// Registration events. #255 adds "blocked".
const (
	EventRegistered = "registered"
	EventRefreshed  = "refreshed"
	EventRejected   = "rejected"
)

// OAuthClientRegistration is the wire/domain shape of one log row.
type OAuthClientRegistration struct {
	ID       string `json:"id"`
	ClientID string `json:"clientId"`
	Origin   string `json:"origin"`
	Event    string `json:"event"`
	// ClientName is the name as it stood at write time (never refreshed).
	ClientName *string `json:"clientName"`
	// MetadataHost is the CIMD Client Identifier URL's hostname; null for DCR.
	MetadataHost *string  `json:"metadataHost"`
	AuthMethod   *string  `json:"authMethod"`
	RedirectURIs []string `json:"redirectUris"`
	Scope        *string  `json:"scope"`
	// Reason is the rejection cause when Event is "rejected".
	Reason    *string `json:"reason"`
	SourceIP  *string `json:"sourceIp"`
	CreatedAt string  `json:"createdAt"`
}

// OAuthClientEvent is one registration event to record.
type OAuthClientEvent struct {
	ClientID     string
	Origin       string
	Event        string
	ClientName   string
	MetadataHost string
	AuthMethod   string
	RedirectURIs []string
	Scope        string
	Reason       string
	SourceIP     string
}

// OAuthClients owns the oauth_client_registrations table.
type OAuthClients struct {
	db  *sql.DB
	clk clock.Clock
	// NewID mints row ids (ids.NewUUID when nil).
	NewID func() string
}

func NewOAuthClients(db *sql.DB, clk clock.Clock) *OAuthClients {
	if clk == nil {
		clk = clock.Real{}
	}
	return &OAuthClients{db: db, clk: clk}
}

// Record appends one event. Failures are logged, never returned: an audit
// write must not break an authorization (same rule as the other writers).
func (o *OAuthClients) Record(ctx context.Context, ev OAuthClientEvent) {
	newID := o.NewID
	if newID == nil {
		newID = ids.NewUUID
	}
	var redirects sql.NullString
	if len(ev.RedirectURIs) > 0 {
		if raw, err := json.Marshal(ev.RedirectURIs); err != nil {
			slog.Warn("audit: redirect_uris marshal failed", "client_id", ev.ClientID, "err", err)
		} else {
			redirects = sql.NullString{String: string(raw), Valid: true}
		}
	}
	if _, err := o.db.ExecContext(ctx,
		`INSERT INTO oauth_client_registrations
		 (id, client_id, origin, event, client_name, metadata_host, auth_method,
		  redirect_uris, scope, reason, source_ip, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		newID(), ev.ClientID, ev.Origin, ev.Event, nullable(ev.ClientName),
		nullable(ev.MetadataHost), nullable(ev.AuthMethod), redirects,
		nullable(ev.Scope), nullable(ev.Reason), nullable(ev.SourceIP),
		o.clk.Now().UTC().Format(isoMillis),
	); err != nil {
		slog.Warn("audit: oauth client registration insert failed",
			"client_id", ev.ClientID, "event", ev.Event, "err", err)
	}
}

// OAuthClientPage is a keyset-paginated result.
type OAuthClientPage struct {
	Rows       []OAuthClientRegistration `json:"rows"`
	NextCursor *string                   `json:"nextCursor"`
}

// OAuthClientFilter narrows the log. All fields are optional.
type OAuthClientFilter struct {
	ClientID string
	Origin   string
	Event    string
	Cursor   string
	Limit    int
}

type oauthCursor struct {
	CreatedAt string `json:"createdAt"`
	ID        string `json:"id"`
}

// List returns a page ordered by (created_at, id) DESC. It is NOT
// account-filtered by design — the caller must be an admin.
func (o *OAuthClients) List(ctx context.Context, f OAuthClientFilter) (OAuthClientPage, error) {
	limit := clampLimit(f.Limit)
	conds := []string{"1 = 1"}
	var args []any
	if f.ClientID != "" {
		conds = append(conds, "client_id = ?")
		args = append(args, f.ClientID)
	}
	if f.Origin != "" {
		conds = append(conds, "origin = ?")
		args = append(args, f.Origin)
	}
	if f.Event != "" {
		conds = append(conds, "event = ?")
		args = append(args, f.Event)
	}
	if c := decodeOAuthCursor(f.Cursor); c != nil {
		conds = append(conds, "(created_at < ? OR (created_at = ? AND id < ?))")
		args = append(args, c.CreatedAt, c.CreatedAt, c.ID)
	}
	query := `SELECT id, client_id, origin, event, client_name, metadata_host,
			auth_method, redirect_uris, scope, reason, source_ip, created_at
		FROM oauth_client_registrations WHERE ` + strings.Join(conds, " AND ") +
		` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit+1)

	rows, err := o.db.QueryContext(ctx, query, args...)
	if err != nil {
		return OAuthClientPage{}, err
	}
	defer rows.Close()
	out := []OAuthClientRegistration{} // non-nil: an empty page serializes as []
	for rows.Next() {
		var r OAuthClientRegistration
		var name, host, auth, redirects, scope, reason, ip sql.NullString
		if err := rows.Scan(&r.ID, &r.ClientID, &r.Origin, &r.Event, &name, &host,
			&auth, &redirects, &scope, &reason, &ip, &r.CreatedAt); err != nil {
			return OAuthClientPage{}, err
		}
		r.ClientName = strPtr(name)
		r.MetadataHost = strPtr(host)
		r.AuthMethod = strPtr(auth)
		r.Scope = strPtr(scope)
		r.Reason = strPtr(reason)
		r.SourceIP = strPtr(ip)
		r.RedirectURIs = []string{}
		if redirects.Valid {
			if err := json.Unmarshal([]byte(redirects.String), &r.RedirectURIs); err != nil {
				slog.Warn("audit: stored redirect_uris unmarshal failed", "id", r.ID, "err", err)
				r.RedirectURIs = []string{}
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return OAuthClientPage{}, err
	}
	var next *string
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		raw, _ := json.Marshal(oauthCursor{CreatedAt: last.CreatedAt, ID: last.ID})
		c := base64.RawURLEncoding.EncodeToString(raw)
		next = &c
	}
	return OAuthClientPage{Rows: out, NextCursor: next}, nil
}

func decodeOAuthCursor(raw string) *oauthCursor {
	if raw == "" {
		return nil
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil
	}
	var c oauthCursor
	if json.Unmarshal(data, &c) != nil || c.CreatedAt == "" || c.ID == "" {
		return nil
	}
	return &c
}

// nullable maps "" to SQL NULL (internal/notify has its own copy; the two
// packages own separate tables and do not import each other).
func nullable(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func strPtr(s sql.NullString) *string {
	if !s.Valid {
		return nil
	}
	v := s.String
	return &v
}
