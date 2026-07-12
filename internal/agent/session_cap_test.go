// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// The maxOwned cap must not count sessions that died under the agent (idle
// janitor, server hangup) — deliberate divergence from Node, whose raw-set
// count starves the cap after N external closes. Post-mortem retained
// sessions (M6) stay OWNED (read_output keeps working); they just don't
// count toward the cap.
package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/endpointsvc"
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

	// Keep every mock so the test can kill transports out from under the
	// manager (server hangup), not via explicit close.
	var mu sync.Mutex
	var mocks []*terminal.MockTransport
	mgr := terminal.NewManager(
		func(context.Context, terminal.FactoryParams) (terminal.Transport, error) {
			m := terminal.NewMockTransport()
			mu.Lock()
			mocks = append(mocks, m)
			mu.Unlock()
			return m, nil
		}, clock.Real{}, 0)
	eps := store.NewEndpoints(db, clock.Real{})
	sess := New(Deps{Manager: mgr, Svc: &endpointsvc.Service{Endpoints: eps}}, "acc", "", 2)
	if err := sess.CreateEndpoint(ctx, store.Endpoint{ID: "ep1", Label: "Box", Host: "h", Port: 22, Username: "u", UserVerification: "required"}); err != nil {
		t.Fatal(err)
	}

	// Fill the cap (2), write some output, then hang up both transports.
	var ids []string
	for i := 0; i < 2; i++ {
		s, err := sess.CreateSession(ctx, "ep1", "cap test")
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		ids = append(ids, s.SessionID)
	}
	if err := sess.SendKeys(ids[0], []string{"text:hello"}); err != nil {
		t.Fatal(err)
	}
	if _, err := sess.CreateSession(ctx, "ep1", "over cap"); err == nil {
		t.Fatal("cap should be enforced while sessions are live")
	}
	mu.Lock()
	for _, m := range mocks {
		_ = m.Close()
	}
	mu.Unlock()
	waitForStatus(t, mgr, ids[0], terminal.StatusClosed)
	waitForStatus(t, mgr, ids[1], terminal.StatusClosed)

	// The agent regains full capacity: dead sessions don't count...
	for i := 0; i < 2; i++ {
		if _, err := sess.CreateSession(ctx, "ep1", "after hangup"); err != nil {
			t.Fatalf("create after external close %d: %v", i, err)
		}
	}
	// ...but the dead ids stay OWNED: post-mortem output remains readable
	// through the agent even after new creates pruned the live count.
	r, err := sess.ReadOutput(ids[0], 0, 100)
	if err != nil {
		t.Fatalf("post-mortem read on retained session: %v", err)
	}
	if string(r.Data) != "hello" {
		t.Fatalf("post-mortem read: %q", r.Data)
	}
	if err := sess.CloseSession(ids[0]); err != nil {
		t.Fatalf("close_session on retained session: %v", err)
	}
}

func waitForStatus(t *testing.T, mgr *terminal.Manager, id string, want terminal.Status) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s := mgr.GetSession(id); s != nil && s.Status == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("session %s never reached %s", id, want)
}

// max_sessions = 0 blocks every create (Node: 0 is honored, not defaulted;
// the Go REST path also 429s at 0 — MCP must match).
func TestCapZeroBlocksCreation(t *testing.T) {
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
	sess := New(Deps{Manager: mgr, Svc: &endpointsvc.Service{Endpoints: eps}}, "acc", "", 0)
	if err := sess.CreateEndpoint(ctx, store.Endpoint{ID: "ep1", Label: "Box", Host: "h", Port: 22, Username: "u", UserVerification: "required"}); err != nil {
		t.Fatal(err)
	}
	if _, err := sess.CreateSession(ctx, "ep1", "blocked"); err == nil {
		t.Fatal("max_sessions=0 must block creation")
	}
	// Negative = "no cap resolved" -> default 5 still applies.
	sess2 := New(Deps{Manager: mgr, Svc: &endpointsvc.Service{Endpoints: eps}}, "acc", "", -1)
	if _, err := sess2.CreateSession(ctx, "ep1", "default cap"); err != nil {
		t.Fatalf("default-cap create: %v", err)
	}
}
