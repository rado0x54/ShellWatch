// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package seed is first-run DB seeding from config (port of src/db/seed.ts):
// the admin account (when none exists), admin passkeys (idempotent on
// credential_id, with the OpenSSH authorized_keys line derived from the COSE
// key), and admin endpoints (only when none exist). Each section is
// independently idempotent. Lives above store so it can import webauthn's
// COSE->OpenSSH conversion without a cycle (webauthn imports store).
package seed

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/webauthn"
)

const isoMillis = "2006-01-02T15:04:05.000Z"

// Result reports what the seed created (mirrors SeedResult).
type Result struct {
	SeededAdminAccount bool
	SeededAdminPasskey bool
	AdminID            string
}

// FromConfig seeds the admin account, passkeys, and endpoints. newID mints
// UUIDs; now supplies the timestamp (injected for testability).
func FromConfig(ctx context.Context, db *sql.DB, cfg *config.Config, newID func() string, now time.Time) (Result, error) {
	ts := now.UTC().Format(isoMillis)
	var res Result

	// 1. Admin account when the DB has no accounts yet.
	var accountCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounts`).Scan(&accountCount); err != nil {
		return res, err
	}
	var adminID string
	if accountCount == 0 {
		adminID = newID()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO accounts (id, name, enabled, max_sessions, last_used_at, created_at, updated_at)
			 VALUES (?, 'admin', 1, 5, ?, ?, ?)`, adminID, ts, ts, ts); err != nil {
			return res, err
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO admin_account (singleton, account_id) VALUES (1, ?)`, adminID); err != nil {
			return res, err
		}
		res.SeededAdminAccount = true
		res.AdminID = adminID
	} else {
		if err := db.QueryRowContext(ctx,
			`SELECT account_id FROM admin_account WHERE singleton = 1`).Scan(&adminID); err != nil {
			return res, fmt.Errorf("no admin account found — database is in an invalid state: %w", err)
		}
	}

	// 2. Admin passkeys (idempotent on credential_id). state defaults to
	// 'active' so a seeded passkey is immediately usable for login.
	for _, pk := range cfg.SeedAdminPasskeys {
		var exists int
		if err := db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM webauthn_credentials WHERE credential_id = ?)`,
			pk.CredentialID).Scan(&exists); err != nil {
			return res, err
		}
		if exists != 0 {
			continue
		}
		pubKey, err := hex.DecodeString(pk.PublicKeyHex)
		if err != nil {
			slog.Warn("seed: bad passkey publicKeyHex, skipping", "credentialId", pk.CredentialID, "err", err)
			continue
		}
		// Non-fatal: an unconvertible key still seeds (openssh line stays NULL).
		openssh := sql.NullString{}
		if line, err := webauthn.CoseToAuthorizedKeys(pubKey, cfg.Security.RpID); err == nil {
			openssh = sql.NullString{String: line, Valid: true}
		}
		transports, _ := json.Marshal(pk.Transports)
		if _, err := db.ExecContext(ctx,
			`INSERT INTO webauthn_credentials (id, account_id, credential_id, public_key, counter, transports, label, public_key_openssh, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			newID(), adminID, pk.CredentialID, pubKey, pk.Counter, string(transports), pk.Label, openssh, ts); err != nil {
			return res, err
		}
		res.SeededAdminPasskey = true
	}

	// 3. Admin endpoints, only on a fresh endpoints table.
	var endpointCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM endpoints`).Scan(&endpointCount); err != nil {
		return res, err
	}
	if endpointCount == 0 {
		for _, ep := range cfg.SeedAdminEndpoints {
			agentForward := ep.AgentForward == nil || *ep.AgentForward // default true
			desc := sql.NullString{}
			if ep.Description != nil {
				desc = sql.NullString{String: *ep.Description, Valid: true}
			}
			if _, err := db.ExecContext(ctx,
				`INSERT INTO endpoints (id, account_id, label, host, port, username, user_verification, agent_forward, description, enabled, created_at, updated_at)
				 VALUES (?, ?, ?, ?, ?, ?, 'required', ?, ?, 1, ?, ?)`,
				newID(), adminID, ep.Label, ep.Parsed.Host, ep.Parsed.Port, ep.Parsed.Username,
				boolInt(agentForward), desc, ts, ts); err != nil {
				return res, err
			}
		}
	}

	return res, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
