// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Sessions REST parity (Phase 3 slice 2): the two 404 goldens plus
// create/list/tail/close behavior driven by a mock transport.
package httpserver

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/golden"
	"github.com/rado0x54/shellwatch/internal/rest"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

func sessionsServer(t *testing.T) (*httptest.Server, *terminal.MockTransport) {
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
	db.ExecContext(ctx, `INSERT INTO accounts (id,name,max_sessions,created_at,updated_at) VALUES ('acc','A',5,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)
	db.ExecContext(ctx, `INSERT INTO endpoints (id,account_id,label,host,port,username,user_verification,agent_forward,enabled,created_at,updated_at) VALUES ('e1','acc','E','h',22,'u','required',1,1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)

	mock := terminal.NewMockTransport()
	mgr := terminal.NewManager(
		func(context.Context, terminal.FactoryParams) (terminal.Transport, error) { return mock, nil },
		clock.Real{}, 0)

	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	endpoints := store.NewEndpoints(db, clock.Real{})
	resolve := auth.Resolver(func(_ context.Context, tok string) *auth.Principal {
		if tok == "ui" {
			return &auth.Principal{AccountID: "acc", Scopes: []string{"ui"}}
		}
		return nil
	})
	handler := New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
		Sessions: &rest.Sessions{Manager: mgr, Endpoints: endpoints},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts, mock
}

func TestSessionsCreate404Golden(t *testing.T) {
	ts, _ := sessionsServer(t)
	status, body := doJSON(t, ts, "POST", "/api/sessions", `{"endpointId":"nope"}`)
	assertEnvelope(t, "err-404-session-endpoint", "/api/sessions", status, body)
}

func TestSessionsTail404Golden(t *testing.T) {
	ts, _ := sessionsServer(t)
	status, body := doJSON(t, ts, "GET", "/api/sessions/sess_deadbeef0000/tail", "")
	assertEnvelope(t, "err-404-session-tail", "/api/sessions/sess_deadbeef0000/tail", status, body)
}

func TestSessionsCreateTailCloseFlow(t *testing.T) {
	ts, _ := sessionsServer(t)
	// Create against the seeded endpoint -> bare session object.
	status, sess := doJSON(t, ts, "POST", "/api/sessions", `{"endpointId":"e1"}`)
	if status != 200 || sess["sessionId"] == nil || sess["status"] != "open" ||
		sess["source"] != "ui" || sess["endpointId"] != "e1" {
		t.Fatalf("create: %d %v", status, sess)
	}
	id, _ := sess["sessionId"].(string)

	// Send input via the manager path is covered in the terminal package;
	// here we just tail (empty until echo) and close.
	tstatus, tbody := doJSON(t, ts, "GET", "/api/sessions/"+id+"/tail", "")
	if tstatus != 200 {
		t.Fatalf("tail: %d", tstatus)
	}
	if _, ok := tbody["data"]; !ok {
		t.Errorf("tail missing data field: %v", tbody)
	}

	cstatus, cbody := doJSON(t, ts, "DELETE", "/api/sessions/"+id, "")
	if cstatus != 200 || cbody["status"] != "closed" {
		t.Fatalf("close: %d %v", cstatus, cbody)
	}
}

// assertEnvelope compares a {request,status,body} envelope to a golden.
func assertEnvelope(t *testing.T, name, path string, status int, body map[string]any) {
	t.Helper()
	got := golden.Normalize(map[string]any{
		"request": map[string]any{"path": path}, "status": float64(status), "body": body,
	}, golden.Options{})
	raw, err := os.ReadFile(filepath.Join(goldensDir, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected any
	_ = json.Unmarshal(raw, &expected)
	if !reflect.DeepEqual(got, expected) {
		a, _ := json.MarshalIndent(expected, "", "  ")
		b, _ := json.MarshalIndent(got, "", "  ")
		t.Errorf("%s mismatch\n--- golden ---\n%s\n--- go ---\n%s", name, a, b)
	}
}
