// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package audit

import (
	"context"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/store"
)

// Restart reconciliation (#263): rows a previous process left unfinished are
// closed out truthfully, staging paths preserved, and returned exactly once.
func TestFileTransfersReconcileInterrupted(t *testing.T) {
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
	log := NewFileTransfers(db, clk)
	str := func(s string) *string { return &s }
	base := FileTransferRow{
		AccountID: "acc", SessionID: "sess_1", EndpointID: "ep", Tier: "link", Direction: "upload",
		Path: "/srv/f", CreatedAt: "2026-03-01T11:00:00.000Z", UpdatedAt: "2026-03-01T11:00:00.000Z",
	}
	seed := func(id, status string, staging *string) {
		r := base
		r.TransferID, r.Status, r.StagingPath = id, status, staging
		log.Save(r)
	}
	seed("xfer_pending", "pending", nil)
	seed("xfer_active", "active", str("/srv/.f.aa.tmp"))
	seed("xfer_committing", "committing", str("/srv/.f.bb.tmp"))
	seed("xfer_done", "completed", nil)

	rows, err := log.ReconcileInterrupted(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("reconciled %d rows, want 3", len(rows))
	}

	get := func(id string) *FileTransferRow {
		t.Helper()
		r, err := log.Get(context.Background(), "acc", id)
		if err != nil || r == nil {
			t.Fatalf("get %s: %v %v", id, r, err)
		}
		return r
	}
	active := get("xfer_active")
	if active.Status != "failed" || *active.Error != "server restarted" || *active.Cleanup != "failed" ||
		*active.StagingPath != "/srv/.f.aa.tmp" || active.CommitOutcome != nil || *active.FinishedAt != "2026-03-01T12:00:00.000Z" {
		t.Errorf("active row: %+v", active)
	}
	committing := get("xfer_committing")
	if committing.Status != "failed" || *committing.CommitOutcome != "unknown" || *committing.Cleanup != "failed" ||
		*committing.StagingPath != "/srv/.f.bb.tmp" {
		t.Errorf("committing row: %+v", committing)
	}
	pending := get("xfer_pending")
	if pending.Status != "failed" || *pending.Error != "server restarted" || pending.Cleanup != nil {
		t.Errorf("pending row: %+v", pending)
	}
	if done := get("xfer_done"); done.Status != "completed" {
		t.Errorf("finished row was touched: %+v", done)
	}

	// Idempotent: a second boot finds nothing to notify about.
	if again, err := log.ReconcileInterrupted(context.Background()); err != nil || len(again) != 0 {
		t.Errorf("second reconciliation: %d rows, %v", len(again), err)
	}
	// Account-scoped read.
	if r, _ := log.Get(context.Background(), "someone-else", "xfer_active"); r != nil {
		t.Error("row visible to another account")
	}
}
