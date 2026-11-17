// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package store

import (
	"context"
	"testing"
)

// TestPushUpsertCreatedRefreshConflict pins the three Upsert outcomes the
// subscribe handler distinguishes: a new row, a refresh by the owner (the
// settings page re-sends on every visit), and another account's endpoint.
func TestPushUpsertCreatedRefreshConflict(t *testing.T) {
	db, err := Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, id := range []string{"a", "b"} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO accounts (id, name, created_at, updated_at) VALUES (?, ?, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`, id, id); err != nil {
			t.Fatal(err)
		}
	}
	subs := NewPushSubs(db, nil)
	const ep = "https://web.push.apple.com/x"

	first, err := subs.Upsert(ctx, "a", ep, "p1", "a1", "id1")
	if err != nil || !first.Created || first.Conflict || first.ID != "id1" {
		t.Fatalf("first upsert = %+v, %v; want created id1", first, err)
	}
	again, err := subs.Upsert(ctx, "a", ep, "p2", "a2", "id2")
	if err != nil || again.Created || again.Conflict || again.ID != "id1" {
		t.Fatalf("refresh = %+v, %v; want existing id1, not created", again, err)
	}
	other, err := subs.Upsert(ctx, "b", ep, "p3", "a3", "id3")
	if err != nil || other.Created || !other.Conflict {
		t.Fatalf("other account = %+v, %v; want conflict", other, err)
	}
}
