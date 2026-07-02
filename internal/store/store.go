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
// the Node backend's behavior).
func Migrate(db *sql.DB) error {
	goose.SetBaseFS(migrations)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("sqlite3"); err != nil {
		return err
	}
	return goose.Up(db, "migrations")
}
