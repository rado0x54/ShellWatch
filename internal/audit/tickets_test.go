// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package audit

import (
	"context"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/store"
)

// Events stamped when they happen (ID, At) keep that order in the audit even
// when their writes run in the opposite order — and even within the same
// millisecond.
func TestTicketEventsKeepEventOrder(t *testing.T) {
	db, err := store.Open("sqlite:" + t.TempDir() + "/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO accounts (id,name,created_at,updated_at) VALUES ('acc','A','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	log := NewTicketEvents(db, clk)
	var ids OrderedIDs
	at := clk.Now()
	ev := func(name string) TicketEvent {
		return TicketEvent{
			ID: ids.Next(at), At: at, AccountID: "acc", TicketID: "tk", Event: name, EndpointID: "ep",
			RedeemTTLSeconds: 300, LifetimeSeconds: 900,
		}
	}
	admitted, ended := ev(TicketAdmitted), ev(TicketEnded)
	clk.Advance(time.Second) // the writes happen later, and in reverse
	log.Record(ended)
	log.Record(admitted)

	page, err := log.List(context.Background(), "acc", TicketEventFilters{TicketID: "tk", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 2 || page.Rows[0].Event != TicketEnded || page.Rows[1].Event != TicketAdmitted {
		t.Fatalf("rows (newest first): %+v", page.Rows)
	}
	if page.Rows[0].CreatedAt != "2026-03-01T12:00:00.000Z" {
		t.Errorf("created_at %s: want the event time, not the write time", page.Rows[0].CreatedAt)
	}
}
