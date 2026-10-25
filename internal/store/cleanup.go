// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Inactive-account cleanup (port of src/db/cleanup.ts). Deletes accounts idle
// past the threshold (default 90 days), excluding admin. Unlike the Node
// version's independent statements, each account's cascade runs in a
// transaction (fixes W9 for this path: a crash mid-delete can't leave an
// account half-removed).
package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
)

const defaultInactivityDays = 90

// CleanupInactiveAccounts deletes accounts whose last activity (last_used_at,
// or created_at when never used) predates the cutoff. Returns deleted ids.
func CleanupInactiveAccounts(ctx context.Context, db *sql.DB, clk clock.Clock, inactivityDays int) ([]string, error) {
	if clk == nil {
		clk = clock.Real{}
	}
	if inactivityDays <= 0 {
		inactivityDays = defaultInactivityDays
	}
	cutoff := clk.Now().UTC().Add(-time.Duration(inactivityDays) * 24 * time.Hour).Format(isoMillis)

	var adminID sql.NullString
	_ = db.QueryRowContext(ctx, `SELECT account_id FROM admin_account WHERE singleton = 1`).Scan(&adminID)

	rows, err := db.QueryContext(ctx,
		`SELECT id FROM accounts WHERE coalesce(last_used_at, created_at) < ? AND (? = '' OR id != ?)`,
		cutoff, adminID.String, adminID.String)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var deleted []string
	for _, id := range ids {
		err := WithTx(ctx, db, func(tx *sql.Tx) error {
			// webauthn_credentials + endpoints aren't FK-cascaded; delete
			// explicitly. audit + push_subscriptions cascade with the account.
			if _, err := tx.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE account_id = ?`, id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM endpoints WHERE account_id = ?`, id); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `DELETE FROM accounts WHERE id = ?`, id)
			return err
		})
		if err != nil {
			return deleted, err
		}
		deleted = append(deleted, id)
	}
	return deleted, nil
}

// RunCleanupJob runs cleanup every 24h until ctx is cancelled.
func RunCleanupJob(ctx context.Context, db *sql.DB, clk clock.Clock, onDeleted func([]string)) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if deleted, err := CleanupInactiveAccounts(ctx, db, clk, defaultInactivityDays); err == nil && len(deleted) > 0 && onDeleted != nil {
				onDeleted(deleted)
			}
		}
	}
}
