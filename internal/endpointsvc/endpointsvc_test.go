// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package endpointsvc

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/rado0x54/shellwatch/internal/audit"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
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

func ptr[T any](v T) *T { return &v }

type auditRec struct{ events []audit.HostKeyEvent }

func (a *auditRec) RecordHostKeyEvent(ev audit.HostKeyEvent) string {
	a.events = append(a.events, ev)
	return ""
}

func TestCreateDefaultsAndValidation(t *testing.T) {
	svc, _, ctx := testService(t)
	if err := svc.Create(ctx, CreateParams{ID: "n", AccountID: "acc", Patch: EndpointPatch{
		Label: ptr(" Box "), Host: ptr(" h "), Description: ptr("  "),
	}}); err != nil {
		t.Fatal(err)
	}
	ep, _ := svc.Endpoints.GetForAccount(ctx, "n", "acc")
	want := store.Endpoint{ID: "n", AccountID: "acc", Label: "Box", Host: "h", Port: 22, Username: "shellwatch",
		UserVerification: "required", AgentForward: true}
	if ep == nil || *ep != want {
		t.Fatalf("create defaults: %+v", ep)
	}
	for name, p := range map[string]CreateParams{
		"no label":   {ID: "x", Patch: EndpointPatch{Host: ptr("h")}},
		"blank host": {ID: "x", Patch: EndpointPatch{Label: ptr("l"), Host: ptr(" ")}},
		"bad uv":     {ID: "x", Patch: EndpointPatch{Label: ptr("l"), Host: ptr("h"), UserVerification: ptr("never")}},
		"long desc":  {ID: "x", Patch: EndpointPatch{Label: ptr("l"), Host: ptr("h"), Description: ptr(strings.Repeat("a", DescriptionMaxLen+1))}},
		"demo id":    {ID: "demo:x", Patch: EndpointPatch{Label: ptr("l"), Host: ptr("h")}},
		"duplicate":  {ID: "own", Patch: EndpointPatch{Label: ptr("l"), Host: ptr("h")}},
	} {
		p.AccountID = "acc"
		if err := svc.Create(ctx, p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestUpdatePatchAuditAndTargetChange(t *testing.T) {
	cases := []struct {
		name          string
		patch         EndpointPatch
		check         func(store.Endpoint) bool
		audit, target bool
	}{
		{"label", EndpointPatch{Label: ptr("L")}, func(e store.Endpoint) bool { return e.Label == "L" && e.HostKey != nil }, false, false},
		{"uv", EndpointPatch{UserVerification: ptr("preferred")}, func(e store.Endpoint) bool { return e.UserVerification == "preferred" }, false, false},
		{"agentForward", EndpointPatch{AgentForward: ptr(false)}, func(e store.Endpoint) bool { return !e.AgentForward }, false, false},
		{"description", EndpointPatch{Description: ptr(" d "), DescriptionSet: true}, func(e store.Endpoint) bool { return e.Description != nil && *e.Description == "d" }, false, false},
		{"username", EndpointPatch{Username: ptr("root")}, func(e store.Endpoint) bool { return e.Username == "root" && e.HostKey != nil }, false, true},
		{"host", EndpointPatch{Host: ptr("h2")}, func(e store.Endpoint) bool { return e.Host == "h2" && e.HostKey == nil }, true, true},
		{"port", EndpointPatch{Port: ptr(int64(2222))}, func(e store.Endpoint) bool { return e.Port == 2222 && e.HostKey == nil }, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, db, ctx := testService(t)
			db.ExecContext(ctx, `UPDATE endpoints SET host_key_fingerprint='SHA256:pin', description='old' WHERE id='own'`)
			rec := &auditRec{}
			var changed []string
			svc.Audit = rec
			svc.OnTargetChanged = func(_, id string) { changed = append(changed, id) }
			ok, err := svc.Update(ctx, UpdateParams{ID: "own", AccountID: "acc", Patch: tc.patch, By: Actor{Via: "MCP", MCPClientName: "c"}})
			if err != nil || !ok {
				t.Fatalf("update: %v %v", ok, err)
			}
			ep, _ := svc.Endpoints.GetForAccount(ctx, "own", "acc")
			if !tc.check(*ep) {
				t.Errorf("merged: %+v", ep)
			}
			if got := len(rec.events) == 1; got != tc.audit {
				t.Errorf("host-key audit %v, want %v", rec.events, tc.audit)
			} else if got && (rec.events[0].Reason != "endpoint host/port updated via MCP" || rec.events[0].MCPClientName != "c") {
				t.Errorf("audit event: %+v", rec.events[0])
			}
			if got := len(changed) == 1; got != tc.target {
				t.Errorf("target changed %v, want %v", changed, tc.target)
			}
		})
	}
	svc, _, ctx := testService(t)
	if ok, err := svc.Update(ctx, UpdateParams{ID: "nope", AccountID: "acc"}); ok || err != nil {
		t.Errorf("missing: %v %v", ok, err)
	}
	if ok, _ := svc.Update(ctx, UpdateParams{ID: "own", AccountID: "other", Patch: EndpointPatch{Label: ptr("x")}}); ok {
		t.Error("cross-account update matched")
	}
}

func TestOpenLimit(t *testing.T) {
	cases := []struct {
		name    string
		max     int
		ok      bool
		opens   int
		wantMax int
	}{
		{"limit of 2", 2, true, 2, 2},
		{"zero blocks", 0, true, 0, 0},
		{"unresolved default", 0, false, DefaultMaxSessions, DefaultMaxSessions},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, ctx := testService(t)
			mgr := terminal.NewManager(func(context.Context, terminal.FactoryParams) (terminal.Transport, error) {
				return terminal.NewMockTransport(), nil
			}, clock.Real{}, 0)
			svc.Sessions = mgr
			svc.MaxSessions = func(context.Context, string) (int, bool) { return tc.max, tc.ok }
			sources := []terminal.Source{terminal.SourceUI, terminal.SourceMCP, terminal.SourceTicket}
			for i := 0; i < tc.opens; i++ {
				tr := terminal.Trigger{Kind: sources[i%3]}
				if tr.Kind == terminal.SourceTicket {
					tr.Ticket = &terminal.TicketTrigger{}
				}
				if _, err := svc.Open(ctx, "acc", "own", tr); err != nil {
					t.Fatalf("open %d: %v", i, err)
				}
			}
			_, err := svc.Open(ctx, "acc", "own", terminal.Trigger{Kind: terminal.SourceUI})
			var limit *terminal.LimitError
			if !errors.As(err, &limit) || limit.Max != tc.wantMax {
				t.Errorf("over the limit: %v", err)
			}
			if _, err := svc.Open(ctx, "acc", "missing", terminal.Trigger{Kind: terminal.SourceUI}); !errors.Is(err, ErrEndpointNotFound) {
				t.Errorf("missing endpoint: %v", err)
			}
		})
	}
}
