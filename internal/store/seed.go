// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// First-run seeding (port of the endpoint path in src/db/seed.ts): pre-provision
// admin endpoints from config on first boot. Idempotent — seeds only when the
// admin account exists and the endpoint isn't already present. (Passkey seeding
// from config is a separate, rarely-used test convenience; add when needed.)
package store

import (
	"context"
	"database/sql"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
)

// SeedAdminEndpoints inserts the configured seed endpoints for the admin
// account (once). newID mints endpoint ids. No-op when there's no admin yet.
func SeedAdminEndpoints(ctx context.Context, db *sql.DB, clk clock.Clock, endpoints []config.SeedEndpoint, newID func() string) (int, error) {
	if len(endpoints) == 0 {
		return 0, nil
	}
	if clk == nil {
		clk = clock.Real{}
	}
	var adminID string
	if err := db.QueryRowContext(ctx, `SELECT account_id FROM admin_account WHERE singleton = 1`).Scan(&adminID); err != nil {
		return 0, nil // no admin -> nothing to seed onto yet
	}

	now := clk.Now().UTC().Format(isoMillis)
	seeded := 0
	for _, e := range endpoints {
		// Skip if an endpoint with the same label already exists for the admin.
		var exists int
		_ = db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM endpoints WHERE account_id = ? AND label = ?)`,
			adminID, e.Label).Scan(&exists)
		if exists != 0 {
			continue
		}
		desc := sql.NullString{}
		if e.Description != nil {
			desc = sql.NullString{String: *e.Description, Valid: true}
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO endpoints (id, account_id, label, host, port, username, user_verification, description, agent_forward, enabled, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, 'required', ?, ?, 1, ?, ?)`,
			newID(), adminID, e.Label, e.Parsed.Host, e.Parsed.Port, e.Parsed.Username,
			desc, boolInt(e.AgentForwardEnabled()), now, now); err != nil {
			return seeded, err
		}
		seeded++
	}
	return seeded, nil
}
