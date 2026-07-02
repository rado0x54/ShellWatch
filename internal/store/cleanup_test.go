// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package store

import (
	"context"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
)

func TestCleanupInactiveAccounts(t *testing.T) {
	db, err := Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// now = 2026-07-01; admin (old, exempt), stale (old), active (recent).
	clk := clock.NewFake(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))

	mk := func(id, lastUsed string) {
		db.ExecContext(ctx, `INSERT INTO accounts (id,name,last_used_at,created_at,updated_at) VALUES (?,?,?,?,?)`,
			id, id, lastUsed, "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z")
	}
	mk("admin", "2026-01-01T00:00:00.000Z")  // old but admin -> exempt
	mk("stale", "2026-01-01T00:00:00.000Z")  // >90d idle -> deleted
	mk("active", "2026-06-30T00:00:00.000Z") // recent -> kept
	db.ExecContext(ctx, `INSERT INTO admin_account (singleton, account_id) VALUES (1, 'admin')`)
	// stale owns an endpoint + credential (must be deleted with it, non-cascaded).
	db.ExecContext(ctx, `INSERT INTO endpoints (id,account_id,label,host,username,created_at,updated_at) VALUES ('e','stale','x','h','u','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')`)
	db.ExecContext(ctx, `INSERT INTO webauthn_credentials (id,account_id,credential_id,public_key,label,created_at) VALUES ('c','stale','cid',x'00','L','2026-01-01T00:00:00.000Z')`)

	deleted, err := CleanupInactiveAccounts(ctx, db, clk, 90)
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0] != "stale" {
		t.Fatalf("deleted: %v", deleted)
	}
	// Admin + active survive; stale and its owned rows are gone.
	for id, want := range map[string]bool{"admin": true, "active": true, "stale": false} {
		var n int
		db.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounts WHERE id = ?`, id).Scan(&n)
		if (n > 0) != want {
			t.Errorf("account %s present=%v, want %v", id, n > 0, want)
		}
	}
	var eps, creds int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM endpoints WHERE account_id='stale'`).Scan(&eps)
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM webauthn_credentials WHERE account_id='stale'`).Scan(&creds)
	if eps != 0 || creds != 0 {
		t.Errorf("stale owned data not deleted: endpoints=%d creds=%d", eps, creds)
	}
}
