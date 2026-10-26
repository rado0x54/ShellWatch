// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Notification log (#252): persist-then-push, keyset pagination, per-account
// retention cap.
package notify

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/store"
)

type fakeHub struct {
	sent []map[string]any
}

func (f *fakeHub) SendToAccount(_ string, msg any) {
	f.sent = append(f.sent, msg.(map[string]any))
}

func testService(t *testing.T) (*Service, *fakeHub) {
	t.Helper()
	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO accounts (id,name,created_at,updated_at) VALUES ('acc','A','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	hub := &fakeHub{}
	svc := NewService(db, clk)
	n := 0
	svc.NewID = func() string { n++; return fmt.Sprintf("ntf-%04d", n) }
	svc.Hub = hub
	return svc, hub
}

func TestPublishPersistsThenPushes(t *testing.T) {
	svc, hub := testService(t)
	ctx := context.Background()

	n := svc.Publish(ctx, PublishParams{
		AccountID: "acc", Type: TypeHostKeyMismatch, Severity: SeverityError,
		Title: "Host key MISMATCH", Detail: "Presented: SHA256:x\nPinned: SHA256:y",
		Payload: map[string]any{"endpointId": "e1", "auditId": "aud-1"},
	})
	if n.ID != "ntf-0001" {
		t.Fatalf("publish id = %q", n.ID)
	}
	// Pushed as notification:new carrying the same object.
	if len(hub.sent) != 1 || hub.sent[0]["type"] != "notification:new" {
		t.Fatalf("hub got %+v", hub.sent)
	}
	if pushed := hub.sent[0]["notification"].(Notification); pushed.ID != n.ID || pushed.Title != n.Title {
		t.Fatalf("pushed notification differs: %+v", pushed)
	}
	// Persisted: the log returns it with detail and typed payload intact.
	page, err := svc.List(ctx, "acc", "", 0)
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("list: %+v err=%v", page, err)
	}
	got := page.Rows[0]
	if got.ID != n.ID || got.Type != TypeHostKeyMismatch || got.Severity != SeverityError ||
		got.Detail == nil || *got.Detail != "Presented: SHA256:x\nPinned: SHA256:y" ||
		got.Payload["endpointId"] != "e1" || got.Payload["auditId"] != "aud-1" {
		t.Fatalf("stored row: %+v", got)
	}
	// Foreign accounts never see it.
	other, _ := svc.List(ctx, "other", "", 0)
	if len(other.Rows) != 0 {
		t.Fatalf("cross-account leak: %+v", other.Rows)
	}
}

func TestListPaginatesNewestFirst(t *testing.T) {
	svc, _ := testService(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		svc.clk.(*clock.Fake).Advance(time.Second)
		svc.Publish(ctx, PublishParams{AccountID: "acc", Type: "t", Severity: SeverityInfo, Title: fmt.Sprintf("n%d", i)})
	}
	page1, err := svc.List(ctx, "acc", "", 2)
	if err != nil || len(page1.Rows) != 2 || page1.NextCursor == nil {
		t.Fatalf("page1: %+v err=%v", page1, err)
	}
	if page1.Rows[0].Title != "n4" || page1.Rows[1].Title != "n3" {
		t.Fatalf("order: %+v", page1.Rows)
	}
	page2, err := svc.List(ctx, "acc", *page1.NextCursor, 2)
	if err != nil || len(page2.Rows) != 2 || page2.Rows[0].Title != "n2" {
		t.Fatalf("page2: %+v err=%v", page2, err)
	}
	page3, err := svc.List(ctx, "acc", *page2.NextCursor, 2)
	if err != nil || len(page3.Rows) != 1 || page3.NextCursor != nil {
		t.Fatalf("page3: %+v err=%v", page3, err)
	}
	// A garbage cursor degrades to page 1, never an error.
	if p, err := svc.List(ctx, "acc", "not-a-cursor", 2); err != nil || len(p.Rows) != 2 {
		t.Fatalf("bad cursor: %+v err=%v", p, err)
	}
}

// Notifications are an audit surface: append-only, nothing is pruned.
func TestLogIsAppendOnly(t *testing.T) {
	svc, _ := testService(t)
	ctx := context.Background()
	const total = 600 // more than any paging default
	for i := 0; i < total; i++ {
		svc.clk.(*clock.Fake).Advance(time.Millisecond)
		svc.Publish(ctx, PublishParams{AccountID: "acc", Type: "t", Severity: SeverityInfo, Title: fmt.Sprintf("n%d", i)})
	}
	var count int
	if err := svc.db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE account_id = 'acc'`).Scan(&count); err != nil || count != total {
		t.Fatalf("count=%d err=%v", count, err)
	}
}
