// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package store

import (
	"testing"

	"github.com/pressly/goose/v3"
)

// Migration 00010 (#326) rebuilds accounts with max_sessions defaulting to
// 20: accounts on the old default 5 move to 20, other values stay, and the
// rebuild of the parent table cascades nothing into its children.
func TestMigration00010RaisesMaxSessionsDefault(t *testing.T) {
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
	if err := goose.UpTo(db, "migrations", 9); err != nil {
		t.Fatalf("migrate to 9: %v", err)
	}
	for _, q := range []string{
		`INSERT INTO accounts (id,name,max_sessions,created_at,updated_at) VALUES ('five','A',5,'t','t'),('three','B',3,'t','t')`,
		`INSERT INTO endpoints (id,account_id,label,host,port,username,user_verification,agent_forward,enabled,created_at,updated_at)
			VALUES ('e','five','L','h',22,'u','required',1,1,'t','t')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("migrate to head: %v", err)
	}
	got := map[string]int{}
	rows, err := db.Query(`SELECT id, max_sessions FROM accounts`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		var n int
		_ = rows.Scan(&id, &n)
		got[id] = n
	}
	rows.Close()
	if got["five"] != 20 || got["three"] != 3 || len(got) != 2 {
		t.Errorf("max_sessions after migration: %v", got)
	}
	var endpoints int
	if err := db.QueryRow(`SELECT COUNT(*) FROM endpoints WHERE account_id = 'five'`).Scan(&endpoints); err != nil || endpoints != 1 {
		t.Errorf("child rows after rebuild: %d %v", endpoints, err)
	}
	if _, err := db.Exec(`INSERT INTO accounts (id,name,created_at,updated_at) VALUES ('new','C','t','t')`); err != nil {
		t.Fatal(err)
	}
	var def int
	if err := db.QueryRow(`SELECT max_sessions FROM accounts WHERE id = 'new'`).Scan(&def); err != nil || def != 20 {
		t.Errorf("column default: %d %v", def, err)
	}
	var fk int
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Errorf("foreign keys left off: %d %v", fk, err)
	}
	if _, err := db.Exec(`INSERT INTO endpoints (id,account_id,label,host,port,username,user_verification,agent_forward,enabled,created_at,updated_at)
		VALUES ('x','nobody','L','h',22,'u','required',1,1,'t','t')`); err == nil {
		t.Error("the endpoints FK no longer points at accounts")
	}
}
