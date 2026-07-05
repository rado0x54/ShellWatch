// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package store owns ShellWatch's SQLite persistence: connection setup
// (modernc.org/sqlite — pure Go, WAL, foreign keys on), embedded goose
// migrations, and the sqlc-generated query layer (gen/).
//
// Design (docs/go-backend-architecture.md §5.6): the schema is carried over
// from the Node backend verbatim; every query on account-owned tables takes
// account_id in SQL; access is honestly synchronous.
package store

import (
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

//go:generate go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 generate

//go:embed migrations/*.sql
var migrations embed.FS

// DefaultDSN mirrors the Node backend's default database location
// (src/db/connection.ts): SHELLWATCH_DB env var or sqlite:./data/shellwatch.db.
const DefaultDSN = "sqlite:./data/shellwatch.db"

// Open opens (creating if necessary) the SQLite database for the given
// connection string. Accepted forms mirror the Node backend:
// "sqlite:<path>", a bare path, or "sqlite::memory:" / ":memory:".
func Open(connectionString string) (*sql.DB, error) {
	if connectionString == "" {
		connectionString = os.Getenv("SHELLWATCH_DB")
	}
	if connectionString == "" {
		connectionString = DefaultDSN
	}
	path := strings.TrimPrefix(connectionString, "sqlite:")

	dsn := path
	if path == ":memory:" {
		// Shared-cache in-memory DB so the pool's connections see one store.
		dsn = "file::memory:?mode=memory&cache=shared"
	} else {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite has a single writer; serializing through one connection avoids
	// SQLITE_BUSY under concurrent writes (same effective model as the Node
	// backend's synchronous better-sqlite3 handle).
	db.SetMaxOpenConns(1)

	for _, pragma := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA foreign_keys = ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}
	return db, nil
}

// Migrate runs the embedded goose migrations (auto-run at startup, matching
// the Node backend's behavior). A database created by the Node backend
// (drizzle) is adopted in place: the schema is byte-identical, so goose's
// baseline is stamped as applied instead of re-run (same-data-dir cutover,
// docs/go-backend-architecture.md §5.6). The reverse direction is covered by
// stamping drizzle's journal on Go-created databases, so a rollback to Node
// doesn't re-run drizzle migration 0000.
func Migrate(db *sql.DB) error {
	if err := adoptNodeDatabase(db); err != nil {
		return err
	}
	goose.SetBaseFS(migrations)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("sqlite3"); err != nil {
		return err
	}
	if err := goose.Up(db, "migrations"); err != nil {
		return err
	}
	return stampDrizzleJournal(db)
}

// drizzleHeadMillis is the `when` of the newest drizzle migration
// (drizzle/meta/_journal.json idx 10, 0010_drop_audit_api_key_columns). The
// Node migration set is frozen ahead of the rewrite, so this constant is the
// cutover watermark in both directions.
const drizzleHeadMillis = 1781446167747

// drizzleMigrationCount is the number of entries in the frozen Node journal.
const drizzleMigrationCount = 11

// adoptNodeDatabase detects a drizzle-managed (Node-created) database and
// stamps goose's version table so the baseline migration is recorded as
// applied instead of failing on the existing tables.
func adoptNodeDatabase(db *sql.DB) error {
	gooseManaged, err := tableExists(db, "goose_db_version")
	if err != nil || gooseManaged {
		return err
	}
	nodeSchema, err := tableExists(db, "accounts")
	if err != nil || !nodeSchema {
		return err // fresh database: goose runs the baseline normally
	}

	// Sanity-check the Node DB is at the drizzle head before adopting: a
	// half-migrated store would fail at runtime in ways far harder to
	// diagnose than this error.
	for _, tbl := range []string{
		"admin_account", "endpoints", "webauthn_credentials", "ssh_keys",
		"audit_session_lifecycle", "audit_signing_requests", "push_subscriptions",
	} {
		ok, err := tableExists(db, tbl)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("existing database is missing table %q — it predates the final Node schema; run the Node backend once to finish its migrations before cutting over", tbl)
		}
	}
	if ok, err := tableExists(db, "__drizzle_migrations"); err == nil && ok {
		var applied int
		if err := db.QueryRow(`SELECT COUNT(*) FROM __drizzle_migrations`).Scan(&applied); err == nil && applied < drizzleMigrationCount {
			return fmt.Errorf("existing database has %d of %d Node migrations applied; run the Node backend once to finish them before cutting over", applied, drizzleMigrationCount)
		}
	}

	// Stamp goose: version-table rows for the bootstrap (0) and the baseline
	// (1), exactly what goose would have written had it created the schema.
	if _, err := db.Exec(`CREATE TABLE goose_db_version (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		version_id INTEGER NOT NULL,
		is_applied INTEGER NOT NULL,
		tstamp TIMESTAMP DEFAULT (datetime('now'))
	)`); err != nil {
		return fmt.Errorf("stamp goose version table: %w", err)
	}
	for _, v := range []int{0, 1} {
		if _, err := db.Exec(`INSERT INTO goose_db_version (version_id, is_applied) VALUES (?, 1)`, v); err != nil {
			return fmt.Errorf("stamp goose version %d: %w", v, err)
		}
	}
	return nil
}

// stampDrizzleJournal records the drizzle head on Go-managed databases so the
// Node backend, pointed back at this data dir, applies nothing instead of
// re-running migration 0000 against the existing schema.
func stampDrizzleJournal(db *sql.DB) error {
	// Same DDL drizzle's sqlite migrator issues (sqlite-core/dialect.js).
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS "__drizzle_migrations" (
		id SERIAL PRIMARY KEY,
		hash text NOT NULL,
		created_at numeric
	)`); err != nil {
		return fmt.Errorf("create drizzle journal: %w", err)
	}
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM __drizzle_migrations`).Scan(&rows); err != nil {
		return err
	}
	if rows > 0 {
		return nil // adopted Node DB: its own journal is authoritative
	}
	_, err := db.Exec(`INSERT INTO __drizzle_migrations (hash, created_at) VALUES ('goose-baseline-stamp', ?)`,
		drizzleHeadMillis)
	return err
}

func tableExists(db *sql.DB, name string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n)
	return n > 0, err
}

// nsp maps a NULL-able string column to *string.
func nsp(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	return &v.String
}
