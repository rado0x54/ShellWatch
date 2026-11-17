// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package store

import (
	"testing"

	"github.com/pressly/goose/v3"
)

// Migration 00008 (#306) rebuilds audit_session_lifecycle to accept the
// 'ticket' source and adds the ticket columns. Every existing row and column
// must survive the rebuild; the status constraint must stay as it was.
func TestMigration00008PreservesSessionAudit(t *testing.T) {
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
	if err := goose.UpTo(db, "migrations", 7); err != nil {
		t.Fatalf("migrate to 7: %v", err)
	}
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	mustExec(`INSERT INTO accounts (id,name,created_at,updated_at) VALUES ('acc','A','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)
	mustExec(`INSERT INTO audit_session_lifecycle (session_id, account_id, endpoint_id, source, status, created_at,
		closed_at, duration_ms, source_ip, mcp_reason, mcp_client_name, mcp_client_version, close_reason)
		VALUES ('s1','acc','e1','mcp','closed','2026-01-01T00:00:00Z','2026-01-01T00:01:00Z',60000,'10.0.0.1','why','Claude','1.0','client.mcp')`)
	if _, err := db.Exec(`INSERT INTO audit_session_lifecycle (session_id, account_id, endpoint_id, source, status, created_at)
		VALUES ('s2','acc','e1','ticket','open','2026-01-01T00:00:00Z')`); err == nil {
		t.Fatal("source 'ticket' accepted before 00008")
	}
	if err := goose.UpTo(db, "migrations", 8); err != nil {
		t.Fatalf("migrate to 8: %v", err)
	}
	var src, reason, name, closeReason string
	var dur int64
	if err := db.QueryRow(`SELECT source, mcp_reason, mcp_client_name, close_reason, duration_ms FROM audit_session_lifecycle WHERE session_id = 's1'`).
		Scan(&src, &reason, &name, &closeReason, &dur); err != nil {
		t.Fatal(err)
	}
	if src != "mcp" || reason != "why" || name != "Claude" || closeReason != "client.mcp" || dur != 60000 {
		t.Errorf("row after rebuild: %s %s %s %s %d", src, reason, name, closeReason, dur)
	}
	mustExec(`INSERT INTO audit_session_lifecycle (session_id, account_id, endpoint_id, source, status, created_at, ticket_id, ticket_label, reason)
		VALUES ('s2','acc','e1','ticket','open','2026-01-01T00:00:00Z','t1','Printer','fix it')`)
	if _, err := db.Exec(`INSERT INTO audit_session_lifecycle (session_id, account_id, endpoint_id, source, status, created_at)
		VALUES ('s3','acc','e1','ticket','bogus','2026-01-01T00:00:00Z')`); err == nil {
		t.Error("status constraint lost in the rebuild")
	}
	mustExec(`INSERT INTO audit_ticket_events (id, account_id, ticket_id, event, created_at, endpoint_id,
		redeem_ttl_seconds, lifetime_seconds, reason_required, agent_forward) VALUES ('ev1','acc','t1','minted','2026-01-01T00:00:00Z','e1',300,900,1,0)`)
	// Both tables cascade with the account.
	mustExec(`PRAGMA foreign_keys = ON`)
	mustExec(`DELETE FROM accounts WHERE id = 'acc'`)
	var n int
	_ = db.QueryRow(`SELECT (SELECT COUNT(*) FROM audit_session_lifecycle) + (SELECT COUNT(*) FROM audit_ticket_events)`).Scan(&n)
	if n != 0 {
		t.Errorf("%d audit rows survived the account", n)
	}
}
