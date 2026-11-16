// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package audit

import (
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// A close racing Create absorbs the Open transition (closing with Previous ==
// opening). The append-only lifecycle log must still record the session: the
// Closing event inserts the row and the terminal event completes it.
func TestAbsorbedOpenStillAudited(t *testing.T) {
	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO accounts (id,name,created_at,updated_at) VALUES ('acc','A','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(time.Unix(1000, 0))
	w := NewWriter(db, clk)

	created := clk.Now()
	sess := &terminal.Session{
		SessionID: "sess_absorbed", AccountID: "acc", EndpointID: "ep", Source: terminal.SourceUI,
		Status: terminal.StatusClosing, CreatedAt: created,
	}
	snapshot := func(string) *terminal.Session { return sess }

	// Destroy hit the session between registration and setStatus(Open):
	// subscribers see closing (from opening), then closed — never open.
	w.handleSessionStatus(terminal.StatusEvent{
		SessionID: sess.SessionID, Status: terminal.StatusClosing,
		Previous: terminal.StatusOpening, Reason: terminal.CloseShutdown, CreatedAt: created,
	}, snapshot)
	clk.Advance(time.Second)
	w.handleSessionStatus(terminal.StatusEvent{
		SessionID: sess.SessionID, Status: terminal.StatusClosed,
		Previous: terminal.StatusClosing, Reason: terminal.CloseShutdown, CreatedAt: created,
	}, snapshot)

	var status, closeReason string
	row := db.QueryRow(`SELECT status, close_reason FROM audit_session_lifecycle WHERE session_id = ?`, sess.SessionID)
	if err := row.Scan(&status, &closeReason); err != nil {
		t.Fatalf("race-absorbed session missing from the audit log: %v", err)
	}
	if status != "closed" || closeReason != string(terminal.CloseShutdown) {
		t.Fatalf("row: status=%q reason=%q", status, closeReason)
	}

	// The normal path (open from opening) must not double-insert via Closing.
	w.handleSessionStatus(terminal.StatusEvent{
		SessionID: sess.SessionID, Status: terminal.StatusClosing,
		Previous: terminal.StatusOpen, Reason: terminal.CloseClientUI, CreatedAt: created,
	}, snapshot)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_session_lifecycle WHERE session_id = ?`, sess.SessionID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("closing-from-open inserted a duplicate row: %d", n)
	}
}

// The none-auth refusal (#311) is one born-resolved row: type
// unauthenticated-endpoint, outcome denied, carrying the observed host key.
// The type is accepted by the migrated CHECK constraint.
func TestRecordUnauthenticatedEndpoint(t *testing.T) {
	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO accounts (id,name,created_at,updated_at) VALUES ('acc','A','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	w := NewWriter(db, clock.NewFake(time.Unix(1000, 0)))
	id := w.RecordHostKeyEvent(HostKeyEvent{
		Type: "unauthenticated-endpoint", Source: "endpoint-auth", AccountID: "acc",
		EndpointID: "e1", EndpointLabel: "Open Box", EndpointAddress: "deploy@h:22",
		Fingerprint: "SHA256:observed", SourceIP: "203.0.113.7",
	})
	if id == "" {
		t.Fatal("insert failed (CHECK constraint not widened?)")
	}
	var typ, outcome, fp, resolved string
	if err := db.QueryRow(`SELECT type, outcome, host_key_fingerprint, resolved_at FROM audit_signing_requests WHERE id = ?`, id).
		Scan(&typ, &outcome, &fp, &resolved); err != nil {
		t.Fatal(err)
	}
	if typ != "unauthenticated-endpoint" || outcome != "denied" || fp != "SHA256:observed" || resolved == "" {
		t.Fatalf("row: type=%q outcome=%q fp=%q resolved=%q", typ, outcome, fp, resolved)
	}
}
