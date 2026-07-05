// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Same-data-dir cutover (H15): a Node-created (drizzle-managed) database is
// adopted by stamping goose's version table; a Go-created database carries a
// drizzle journal stamp so a rollback to Node applies nothing.
package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// nodeDatabase builds a real Node-backend database by replaying the actual
// drizzle migrations (drizzle/*.sql) and journal bookkeeping.
func nodeDatabase(t *testing.T) *sql.DB {
	t.Helper()
	db, err := Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	dir := filepath.Join("..", "..", "drizzle")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	if len(files) != drizzleMigrationCount {
		t.Fatalf("expected %d drizzle migrations, found %d — update drizzleMigrationCount/drizzleHeadMillis", drizzleMigrationCount, len(files))
	}
	for _, f := range files {
		raw, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range strings.Split(string(raw), "--> statement-breakpoint") {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err := db.Exec(stmt); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
		}
	}
	// Drizzle's own bookkeeping.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS "__drizzle_migrations" (id SERIAL PRIMARY KEY, hash text NOT NULL, created_at numeric)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < drizzleMigrationCount; i++ {
		if _, err := db.Exec(`INSERT INTO __drizzle_migrations (hash, created_at) VALUES ('h', ?)`, drizzleHeadMillis-int64(drizzleMigrationCount)+int64(i)+1); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestMigrateAdoptsNodeDatabase(t *testing.T) {
	db := nodeDatabase(t)
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate over Node DB: %v", err)
	}
	// Goose stamped, data usable, and re-running stays clean.
	var v int
	if err := db.QueryRow(`SELECT MAX(version_id) FROM goose_db_version`).Scan(&v); err != nil || v != 1 {
		t.Fatalf("goose stamp: v=%d err=%v", v, err)
	}
	if _, err := db.Exec(`INSERT INTO accounts (id,name,max_sessions,created_at,updated_at) VALUES ('a','A',5,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("adopted DB unusable: %v", err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

func TestMigrateRejectsHalfMigratedNodeDatabase(t *testing.T) {
	db, err := Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Only an early-era table: schema predates the final Node migrations.
	if _, err := db.Exec(`CREATE TABLE accounts (id text PRIMARY KEY, name text)`); err != nil {
		t.Fatal(err)
	}
	err = Migrate(db)
	if err == nil || !strings.Contains(err.Error(), "run the Node backend once") {
		t.Fatalf("expected adoption guard error, got %v", err)
	}
}

func TestMigrateStampsDrizzleJournalOnFreshDatabase(t *testing.T) {
	db, err := Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	var createdAt int64
	if err := db.QueryRow(`SELECT created_at FROM __drizzle_migrations ORDER BY created_at DESC LIMIT 1`).Scan(&createdAt); err != nil {
		t.Fatalf("drizzle journal not stamped: %v", err)
	}
	if createdAt != drizzleHeadMillis {
		t.Fatalf("stamp = %d, want %d", createdAt, drizzleHeadMillis)
	}
	// Drizzle's skip rule is `last.created_at < migration.folderMillis`; the
	// head stamp means Node applies nothing on rollback.
	var rows int
	_ = db.QueryRow(`SELECT COUNT(*) FROM __drizzle_migrations`).Scan(&rows)
	if rows != 1 {
		t.Fatalf("journal rows = %d, want 1", rows)
	}
}
