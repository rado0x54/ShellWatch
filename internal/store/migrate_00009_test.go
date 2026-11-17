// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package store

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
)

// Migration 00009 (#319) folds every mcp_reason into the generic reason:
// MCP session rows move theirs into reason (ticket rows keep theirs), the
// signing column is renamed, and stored session-connect-failed payloads
// rename their mcpReason key.
func TestMigration00009GenericReason(t *testing.T) {
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
	if err := goose.UpTo(db, "migrations", 8); err != nil {
		t.Fatalf("migrate to 8: %v", err)
	}
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	mustExec(`INSERT INTO accounts (id,name,created_at,updated_at) VALUES ('acc','A','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)
	mustExec(`INSERT INTO audit_session_lifecycle (session_id, account_id, endpoint_id, source, status, created_at, mcp_reason, mcp_client_name)
		VALUES ('s-mcp','acc','e1','mcp','open','2026-01-01T00:00:00Z','deploy','Claude')`)
	mustExec(`INSERT INTO audit_session_lifecycle (session_id, account_id, endpoint_id, source, status, created_at, ticket_id, reason)
		VALUES ('s-ticket','acc','e1','ticket','open','2026-01-01T00:00:00Z','t1','fix it')`)
	mustExec(`INSERT INTO audit_session_lifecycle (session_id, account_id, endpoint_id, source, status, created_at)
		VALUES ('s-ui','acc','e1','ui','open','2026-01-01T00:00:00Z')`)
	mustExec(`INSERT INTO audit_signing_requests (id, account_id, type, source, created_at, mcp_reason)
		VALUES ('a1','acc','key-approve','endpoint-auth','2026-01-01T00:00:00Z','guest says')`)
	mustExec(`INSERT INTO notifications (id, account_id, type, severity, title, payload, created_at) VALUES
		('n1','acc','session-connect-failed','warning','t','{"trigger":"mcp","mcpReason":"deploy","error":"x"}','2026-01-01T00:00:00Z'),
		('n2','acc','host-key-mismatch','error','t','{"mcpReason":"untouched"}','2026-01-01T00:00:00Z'),
		('n3','acc','session-connect-failed','warning','t',NULL,'2026-01-01T00:00:00Z')`)

	if err := goose.UpTo(db, "migrations", 9); err != nil {
		t.Fatalf("migrate to 9: %v", err)
	}

	for id, want := range map[string]sql.NullString{
		"s-mcp":    {String: "deploy", Valid: true},
		"s-ticket": {String: "fix it", Valid: true},
		"s-ui":     {},
	} {
		var got sql.NullString
		if err := db.QueryRow(`SELECT reason FROM audit_session_lifecycle WHERE session_id = ?`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s: reason = %v, want %v", id, got, want)
		}
	}
	var name string
	if err := db.QueryRow(`SELECT mcp_client_name FROM audit_session_lifecycle WHERE session_id = 's-mcp'`).Scan(&name); err != nil || name != "Claude" {
		t.Errorf("mcp_client_name after migration: %q %v", name, err)
	}
	if _, err := db.Exec(`SELECT mcp_reason FROM audit_session_lifecycle`); err == nil {
		t.Error("audit_session_lifecycle.mcp_reason still exists")
	}

	var sig string
	if err := db.QueryRow(`SELECT reason FROM audit_signing_requests WHERE id = 'a1'`).Scan(&sig); err != nil || sig != "guest says" {
		t.Errorf("signing reason: %q %v", sig, err)
	}
	if _, err := db.Exec(`SELECT mcp_reason FROM audit_signing_requests`); err == nil {
		t.Error("audit_signing_requests.mcp_reason still exists")
	}

	for id, want := range map[string]sql.NullString{
		"n1": {String: `{"trigger":"mcp","error":"x","reason":"deploy"}`, Valid: true},
		"n2": {String: `{"mcpReason":"untouched"}`, Valid: true},
		"n3": {},
	} {
		var got sql.NullString
		if err := db.QueryRow(`SELECT payload FROM notifications WHERE id = ?`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s: payload = %v, want %v", id, got, want)
		}
	}
}
