// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package agent

import (
	"context"
	"testing"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/store"
)

func TestSessionEndpointMutations(t *testing.T) {
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

	sess := New(Deps{Endpoints: store.NewEndpoints(db, clock.Real{})}, "acc", "1.2.3.4", 5)

	// Create.
	if err := sess.CreateEndpoint(ctx, store.Endpoint{ID: "ep1", Label: "Box", Host: "h", Port: 22, Username: "u", UserVerification: "required"}); err != nil {
		t.Fatal(err)
	}
	ep, _ := sess.GetEndpoint(ctx, "ep1")
	if ep == nil || ep.Label != "Box" || ep.AccountID != "acc" {
		t.Fatalf("create: %+v", ep)
	}

	// Update (partial patch merges).
	ok, err := sess.UpdateEndpoint(ctx, "ep1", map[string]any{"label": "Renamed", "port": float64(2222), "agentForward": true})
	if err != nil || !ok {
		t.Fatalf("update: ok=%v err=%v", ok, err)
	}
	ep, _ = sess.GetEndpoint(ctx, "ep1")
	if ep.Label != "Renamed" || ep.Port != 2222 || !ep.AgentForward || ep.Host != "h" {
		t.Fatalf("update merge wrong: %+v", ep)
	}

	// Update a missing endpoint -> false.
	if ok, _ := sess.UpdateEndpoint(ctx, "nope", map[string]any{"label": "x"}); ok {
		t.Error("update of missing endpoint should return false")
	}
	// Cross-account isolation: another account can't touch ep1.
	other := New(Deps{Endpoints: store.NewEndpoints(db, clock.Real{})}, "acc2", "", 5)
	if ok, _ := other.DeleteEndpoint(ctx, "ep1"); ok {
		t.Error("cross-account delete should not match")
	}

	// Delete.
	ok, err = sess.DeleteEndpoint(ctx, "ep1")
	if err != nil || !ok {
		t.Fatalf("delete: ok=%v err=%v", ok, err)
	}
	if ep, _ := sess.GetEndpoint(ctx, "ep1"); ep != nil {
		t.Error("endpoint still present after delete")
	}
}
