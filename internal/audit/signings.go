// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package audit

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// SigningRow is one signing-request audit record (audit_signing_requests).
type SigningRow struct {
	ID               string  `json:"id"`
	AccountID        string  `json:"accountId"`
	Type             string  `json:"type"`
	Source           string  `json:"source"`
	CreatedAt        string  `json:"createdAt"`
	ResolvedAt       *string `json:"resolvedAt"`
	Outcome          *string `json:"outcome"`
	LatencyMs        *int64  `json:"latencyMs"`
	SourceIP         *string `json:"sourceIp"`
	EndpointLabel    *string `json:"endpointLabel"`
	EndpointAddress  *string `json:"endpointAddress"`
	SessionID        *string `json:"sessionId"`
	MCPReason        *string `json:"mcpReason"`
	MCPClientName    *string `json:"mcpClientName"`
	MCPClientVersion *string `json:"mcpClientVersion"`
	ClientHostname   *string `json:"clientHostname"`
	ClientOS         *string `json:"clientOs"`
	ClientVersion    *string `json:"clientVersion"`
	CredentialID     *string `json:"credentialId"`
	PasskeyLabel     *string `json:"passkeyLabel"`
	UserVerification *string `json:"userVerification"`
	KeyLabel         *string `json:"keyLabel"`
	KeyFingerprint   *string `json:"keyFingerprint"`
	CancelReason     *string `json:"cancelReason"`
}

// SigningFilters narrow a signing-request page.
type SigningFilters struct {
	Source  string
	Outcome string
	From    string
	To      string
}

// Signings reads the signing-request audit table.
type Signings struct {
	db *sql.DB
}

func NewSignings(db *sql.DB) *Signings { return &Signings{db: db} }

const signingColumns = `id, account_id, type, source, created_at, resolved_at, outcome,
	latency_ms, source_ip, endpoint_label, endpoint_address, session_id,
	mcp_reason, mcp_client_name, mcp_client_version, client_hostname, client_os, client_version,
	credential_id, passkey_label, user_verification, key_label, key_fingerprint, cancel_reason`

func scanSigning(sc interface{ Scan(...any) error }) (SigningRow, error) {
	var r SigningRow
	var resolvedAt, outcome, sourceIP, epLabel, epAddr, sessID, mcpReason, mcpName, mcpVer,
		cHost, cOS, cVer, credID, passLabel, uv, keyLabel, keyFp, cancel sql.NullString
	var latency sql.NullInt64
	if err := sc.Scan(&r.ID, &r.AccountID, &r.Type, &r.Source, &r.CreatedAt, &resolvedAt, &outcome,
		&latency, &sourceIP, &epLabel, &epAddr, &sessID, &mcpReason, &mcpName, &mcpVer,
		&cHost, &cOS, &cVer, &credID, &passLabel, &uv, &keyLabel, &keyFp, &cancel); err != nil {
		return SigningRow{}, err
	}
	r.ResolvedAt, r.Outcome, r.LatencyMs = ns(resolvedAt), ns(outcome), ni(latency)
	r.SourceIP, r.EndpointLabel, r.EndpointAddress, r.SessionID = ns(sourceIP), ns(epLabel), ns(epAddr), ns(sessID)
	r.MCPReason, r.MCPClientName, r.MCPClientVersion = ns(mcpReason), ns(mcpName), ns(mcpVer)
	r.ClientHostname, r.ClientOS, r.ClientVersion = ns(cHost), ns(cOS), ns(cVer)
	r.CredentialID, r.PasskeyLabel, r.UserVerification = ns(credID), ns(passLabel), ns(uv)
	r.KeyLabel, r.KeyFingerprint, r.CancelReason = ns(keyLabel), ns(keyFp), ns(cancel)
	return r, nil
}

// List returns an account-scoped, keyset-paginated page ordered by
// (created_at, id) DESC.
func (s *Signings) List(ctx context.Context, accountID string, f SigningFilters, cursorStr string, limit int) (Page[SigningRow], error) {
	limit = clampLimit(limit)
	conds := []string{"account_id = ?"}
	args := []any{accountID}
	if f.Source != "" {
		conds = append(conds, "source = ?")
		args = append(args, f.Source)
	}
	if f.Outcome != "" {
		conds = append(conds, "outcome = ?")
		args = append(args, f.Outcome)
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
		conds = append(conds, "(created_at < ? OR (created_at = ? AND id < ?))")
		args = append(args, c.CreatedAt, c.CreatedAt, c.ID)
	}

	query := `SELECT ` + signingColumns + ` FROM audit_signing_requests WHERE ` +
		strings.Join(conds, " AND ") + ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit+1)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return Page[SigningRow]{}, err
	}
	defer rows.Close()
	var out []SigningRow
	for rows.Next() {
		r, err := scanSigning(rows)
		if err != nil {
			return Page[SigningRow]{}, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return Page[SigningRow]{}, err
	}
	next := paginate(&out, limit, func(r SigningRow) cursor { return cursor{CreatedAt: r.CreatedAt, ID: r.ID} })
	return Page[SigningRow]{Rows: out, NextCursor: next}, nil
}

// GetByID returns one signing-request record scoped to the account (nil absent).
func (s *Signings) GetByID(ctx context.Context, accountID, id string) (*SigningRow, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+signingColumns+` FROM audit_signing_requests WHERE account_id = ? AND id = ?`,
		accountID, id)
	r, err := scanSigning(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}
