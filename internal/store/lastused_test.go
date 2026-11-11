// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package store

import (
	"context"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/store/gen"
)

// CloseAndFlush writes the dirty tail and then refuses every later Touch: a
// straggler handler that outlives the HTTP drain can neither dirty state the
// final flush missed nor cause a flusher DB write after it (the "flush is the
// last write before db.Close" shutdown invariant).
func TestCloseAndFlushDiscardsLaterTouches(t *testing.T) {
	db, err := Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO accounts (id, name, created_at, updated_at) VALUES ('acc-1', 'Test', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
	); err != nil {
		t.Fatal(err)
	}

	clk := clock.NewFake(time.Unix(1000, 0))
	f := NewLastUsedFlusher(db, clk)
	f.Touch("acc-1")
	f.CloseAndFlush(ctx)

	q := gen.New(db)
	acc, err := q.GetAccount(ctx, "acc-1")
	if err != nil {
		t.Fatal(err)
	}
	if !acc.LastUsedAt.Valid {
		t.Fatal("CloseAndFlush dropped the dirty tail")
	}
	flushed := acc.LastUsedAt.String

	// A Touch landing after the close is discarded — no later Flush may
	// produce a DB write. Advance the clock so a leak would be visible.
	clk.Advance(time.Minute)
	f.Touch("acc-1")
	f.Flush(ctx)
	acc, err = q.GetAccount(ctx, "acc-1")
	if err != nil {
		t.Fatal(err)
	}
	if acc.LastUsedAt.String != flushed {
		t.Fatalf("post-close Touch reached the DB: %q -> %q", flushed, acc.LastUsedAt.String)
	}
}
