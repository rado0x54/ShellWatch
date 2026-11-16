// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package store

import (
	"testing"

	"github.com/pressly/goose/v3"
)

// Migration 00007 (#311) rebuilds audit_signing_requests to accept the
// 'unauthenticated-endpoint' type. On an existing database every row and
// column — including the host-key columns added by 00002 — must survive the
// rebuild, and the outcome constraint must stay as it was.
func TestMigration00007PreservesSigningAudit(t *testing.T) {
	db, err := Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	goose.SetBaseFS(migrations)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("sqlite3"); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpTo(db, "migrations", 6); err != nil {
		t.Fatalf("migrate to 6: %v", err)
	}
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	mustExec(`INSERT INTO accounts (id,name,created_at,updated_at) VALUES ('acc','A','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)
	mustExec(`INSERT INTO audit_signing_requests (id, account_id, type, source, created_at, resolved_at, outcome,
		endpoint_id, host_key_fingerprint, host_key_prior_fingerprint, host_key_pinned, key_label)
		VALUES ('r1','acc','host-key-mismatch','endpoint-auth','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','denied',
		'e1','SHA256:obs','SHA256:pin',1,'k')`)
	if _, err := db.Exec(`INSERT INTO audit_signing_requests (id, account_id, type, source, created_at)
		VALUES ('r2','acc','unauthenticated-endpoint','endpoint-auth','2026-01-01T00:00:00Z')`); err == nil {
		t.Fatal("v6 schema must reject the new type (test premise)")
	}

	if err := Migrate(db); err != nil {
		t.Fatalf("migrate to head: %v", err)
	}
	var endpointID, fp, prior, keyLabel string
	var pinned int
	if err := db.QueryRow(`SELECT endpoint_id, host_key_fingerprint, host_key_prior_fingerprint, host_key_pinned, key_label
		FROM audit_signing_requests WHERE id = 'r1'`).Scan(&endpointID, &fp, &prior, &pinned, &keyLabel); err != nil {
		t.Fatalf("row lost in rebuild: %v", err)
	}
	if endpointID != "e1" || fp != "SHA256:obs" || prior != "SHA256:pin" || pinned != 1 || keyLabel != "k" {
		t.Fatalf("columns lost in rebuild: %q %q %q %d %q", endpointID, fp, prior, pinned, keyLabel)
	}
	mustExec(`INSERT INTO audit_signing_requests (id, account_id, type, source, created_at, resolved_at, outcome)
		VALUES ('r2','acc','unauthenticated-endpoint','endpoint-auth','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','denied')`)
	if _, err := db.Exec(`INSERT INTO audit_signing_requests (id, account_id, type, source, created_at, outcome)
		VALUES ('r3','acc','unauthenticated-endpoint','endpoint-auth','2026-01-01T00:00:00Z','refused')`); err == nil {
		t.Fatal("the outcome constraint must be unchanged")
	}
	var idx int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='audit_signing_requests_account_created_idx'`).Scan(&idx); err != nil || idx != 1 {
		t.Fatalf("index missing after rebuild: %d %v", idx, err)
	}
}
