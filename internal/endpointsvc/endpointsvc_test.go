// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package endpointsvc

import (
	"context"
	"database/sql"
	"testing"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/store"
)

func testService(t *testing.T) (*Service, *sql.DB, context.Context) {
	t.Helper()
	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db.ExecContext(ctx, `INSERT INTO accounts (id,name,show_demo_endpoints,created_at,updated_at) VALUES ('acc','A',0,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)
	db.ExecContext(ctx, `INSERT INTO endpoints (id,account_id,label,host,port,username,user_verification,agent_forward,enabled,created_at,updated_at) VALUES ('own',?,'Own','h',22,'u','required',1,1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, "acc")

	demoSvc := demo.NewService([]config.SeedEndpoint{{
		Label:  "Demo",
		Parsed: config.EndpointAddress{Host: "demo.example", Port: 22, Username: "sw"},
	}})
	return &Service{Endpoints: store.NewEndpoints(db, clock.Real{}), Demo: demoSvc}, db, ctx
}

func TestDemoMergeAndResolution(t *testing.T) {
	svc, db, ctx := testService(t)
	demoID := svc.Demo.List("acc")[0].ID

	// Toggle off: list shows own endpoints only...
	eps, err := svc.ListForAccount(ctx, "acc")
	if err != nil || len(eps) != 1 || eps[0].ID != "own" || eps[0].IsDemo {
		t.Fatalf("toggle off: %+v err=%v", eps, err)
	}
	// ...but a known demo id still resolves (read/inspect stays possible).
	ep, err := svc.GetForAccount(ctx, demoID, "acc")
	if err != nil || ep == nil || !ep.IsDemo || ep.Host != "demo.example" {
		t.Fatalf("demo get with toggle off: %+v err=%v", ep, err)
	}

	// Toggle on: own first, then demo (order pinned by the list golden).
	db.ExecContext(ctx, `UPDATE accounts SET show_demo_endpoints=1 WHERE id='acc'`)
	eps, err = svc.ListForAccount(ctx, "acc")
	if err != nil || len(eps) != 2 || eps[0].ID != "own" || !eps[1].IsDemo {
		t.Fatalf("toggle on: %+v err=%v", eps, err)
	}

	// Ref resolution covers both stored and demo endpoints.
	ref, err := svc.RefForAccount(ctx, "own", "acc")
	if err != nil || ref == nil || ref.Host != "h" || ref.Port != 22 || !ref.AgentForward {
		t.Fatalf("own ref: %+v err=%v", ref, err)
	}
	ref, err = svc.RefForAccount(ctx, demoID, "acc")
	if err != nil || ref == nil || ref.Host != "demo.example" || ref.AccountID != "acc" {
		t.Fatalf("demo ref: %+v err=%v", ref, err)
	}

	// Foreign and unknown ids are indistinguishable: nil, no error.
	if ep, err := svc.GetForAccount(ctx, "own", "other-acc"); ep != nil || err != nil {
		t.Fatalf("foreign id must resolve to nil: %+v err=%v", ep, err)
	}
	if ref, err := svc.RefForAccount(ctx, "demo:nope", "acc"); ref != nil || err != nil {
		t.Fatalf("unknown demo id must resolve to nil: %+v err=%v", ref, err)
	}
}
