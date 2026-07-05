// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// The maxOwned cap must not count sessions the manager already closed (idle
// janitor, server hangup) — deliberate divergence from Node, whose raw-set
// count starves the cap after N external closes.
package agent

import (
	"context"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

func TestCapIgnoresExternallyClosedSessions(t *testing.T) {
	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db.ExecContext(ctx, `INSERT INTO accounts (id,name,created_at,updated_at) VALUES ('acc','A','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)

	mgr := terminal.NewManager(
		func(context.Context, terminal.FactoryParams) (terminal.Transport, error) {
			return terminal.NewMockTransport(), nil
		}, clock.Real{}, 0)
	eps := store.NewEndpoints(db, clock.Real{})
	sess := New(Deps{Manager: mgr, Endpoints: eps}, "acc", "", 2)
	if err := sess.CreateEndpoint(ctx, store.Endpoint{ID: "ep1", Label: "Box", Host: "h", Port: 22, Username: "u", UserVerification: "required"}); err != nil {
		t.Fatal(err)
	}

	// Fill the cap (2), then have the MANAGER close both — simulating the
	// idle-timeout janitor / a server hangup, not an agent-initiated close.
	var ids []string
	for i := 0; i < 2; i++ {
		s, err := sess.CreateSession(ctx, "ep1", "cap test")
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		ids = append(ids, s.SessionID)
	}
	if _, err := sess.CreateSession(ctx, "ep1", "over cap"); err == nil {
		t.Fatal("cap should be enforced while sessions are live")
	}
	for _, id := range ids {
		mgr.Close(id, terminal.CloseIdleTimeout)
	}
	// Close is async through the transport pump; wait for the registry to drop them.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(mgr.ListForAccount("acc")) == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The agent must regain full capacity: stale ids may not starve the cap.
	for i := 0; i < 2; i++ {
		if _, err := sess.CreateSession(ctx, "ep1", "after janitor"); err != nil {
			t.Fatalf("create after external close %d: %v", i, err)
		}
	}
}
