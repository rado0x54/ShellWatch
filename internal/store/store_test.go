// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package store

import (
	"context"
	"testing"

	"github.com/rado0x54/shellwatch/internal/store/gen"
)

// TestOpenMigrateQuery proves the Phase 1 persistence pipeline end to end:
// pure-Go driver, embedded goose baseline, sqlc-generated queries.
func TestOpenMigrateQuery(t *testing.T) {
	db, err := Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Re-running migrations must be a no-op (startup idempotency).
	if err := Migrate(db); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	ctx := context.Background()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO accounts (id, name, created_at, updated_at) VALUES ('acc-1', 'Test', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
	); err != nil {
		t.Fatalf("insert: %v", err)
	}

	q := gen.New(db)
	acc, err := q.GetAccount(ctx, "acc-1")
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if acc.Name != "Test" || acc.Enabled != 1 || acc.MaxSessions != 5 || acc.ShowDemoEndpoints != 1 {
		t.Fatalf("unexpected defaults: %+v", acc)
	}

	// Foreign keys must be enforced (PRAGMA foreign_keys=ON).
	if _, err := db.ExecContext(ctx,
		`INSERT INTO endpoints (id, account_id, label, host, username, created_at, updated_at) VALUES ('e1', 'missing', 'x', 'h', 'u', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
	); err == nil {
		t.Fatal("expected FK violation for endpoint with unknown account")
	}

	// CHECK constraints carried over from the Node schema.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO audit_session_lifecycle (session_id, account_id, endpoint_id, source, status, created_at) VALUES ('s1', 'acc-1', 'e1', 'bogus', 'open', '2026-01-01T00:00:00Z')`,
	); err == nil {
		t.Fatal("expected CHECK violation for invalid source")
	}
}
