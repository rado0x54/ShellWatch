// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Write-behind last-used tracking (port of the dirty-map batching in
// src/db/repositories/account-repo.ts): the bearer gate marks accounts on
// the hot path; a janitor flushes to SQLite periodically and on shutdown,
// so authentication never writes synchronously.
package store

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/store/gen"
)

// isoMillis matches Node's new Date().toISOString() rendering.
const isoMillis = "2006-01-02T15:04:05.000Z"

type LastUsedFlusher struct {
	mu    sync.Mutex
	dirty map[string]string // accountID -> ISO timestamp
	q     *gen.Queries
	clk   clock.Clock
}

func NewLastUsedFlusher(db *sql.DB, clk clock.Clock) *LastUsedFlusher {
	if clk == nil {
		clk = clock.Real{}
	}
	return &LastUsedFlusher{dirty: make(map[string]string), q: gen.New(db), clk: clk}
}

// Touch records activity; cheap and non-blocking (map write under mutex).
func (f *LastUsedFlusher) Touch(accountID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dirty[accountID] = f.clk.Now().UTC().Format(isoMillis)
}

// Flush writes all dirty timestamps. Failures are logged, not fatal —
// last-used is advisory (same policy as the Node repo).
func (f *LastUsedFlusher) Flush(ctx context.Context) {
	f.mu.Lock()
	batch := f.dirty
	f.dirty = make(map[string]string)
	f.mu.Unlock()
	for id, ts := range batch {
		if err := f.q.TouchAccountLastUsed(ctx, gen.TouchAccountLastUsedParams{
			LastUsedAt: sql.NullString{String: ts, Valid: true}, ID: id,
		}); err != nil {
			slog.Warn("last-used flush failed", "account", id, "err", err)
		}
	}
}

// Run flushes every interval until ctx is cancelled (60s in Node), with a
// final flush on the way out so shutdown captures the tail.
func (f *LastUsedFlusher) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			f.Flush(context.Background())
			return
		case <-t.C:
			f.Flush(ctx)
		}
	}
}
