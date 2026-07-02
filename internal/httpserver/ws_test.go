// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// WebSocket hub parity (Phase 3 slice 4): the ws-sessions-changed golden plus
// attach/control/output behavior, driven by a real coder/websocket client
// through the hub against a mock-transport session.
package httpserver

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/golden"
	"github.com/rado0x54/shellwatch/internal/terminal"
	wshub "github.com/rado0x54/shellwatch/internal/ws"
)

func wsServer(t *testing.T) (*httptest.Server, *terminal.Manager, *terminal.MockTransport) {
	t.Helper()
	mock := terminal.NewMockTransport()
	mgr := terminal.NewManager(
		func(context.Context, terminal.FactoryParams) (terminal.Transport, error) { return mock, nil },
		clock.Real{}, 0)
	hub := wshub.NewHub(mgr)
	t.Cleanup(hub.Close)

	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	resolve := auth.Resolver(func(_ context.Context, tok string) *auth.Principal {
		if tok == "ui" {
			return &auth.Principal{AccountID: "acc", Scopes: []string{"ui"}}
		}
		return nil
	})
	handler := New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
		WSHub: hub,
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts, mgr, mock
}

func dialWS(t *testing.T, ts *httptest.Server) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	c, _, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{
		Subprotocols: []string{auth.WSBearerSubprotocol, "ui"},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close(websocket.StatusNormalClosure, "") })
	return c
}

func readMsg(t *testing.T, c *websocket.Conn) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, raw, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

func writeMsg(t *testing.T, c *websocket.Conn, msg any) {
	t.Helper()
	raw, _ := json.Marshal(msg)
	if err := c.Write(context.Background(), websocket.MessageText, raw); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestWSSessionsChangedGolden(t *testing.T) {
	ts, mgr, _ := wsServer(t)
	// A UI session exists before the client connects.
	ep := terminal.EndpointRef{ID: "test-server", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	if _, err := mgr.Create(context.Background(), ep, "acc", terminal.Trigger{Kind: terminal.SourceUI}); err != nil {
		t.Fatal(err)
	}

	c := dialWS(t, ts)
	msg := readMsg(t, c) // connect-time sessions:changed

	got := golden.Normalize(msg, golden.Options{})
	raw, _ := os.ReadFile(filepath.Join(goldensDir, "ws-sessions-changed.json"))
	var expected any
	_ = json.Unmarshal(raw, &expected)
	if !reflect.DeepEqual(got, expected) {
		a, _ := json.MarshalIndent(expected, "", "  ")
		b, _ := json.MarshalIndent(got, "", "  ")
		t.Errorf("ws-sessions-changed mismatch\n--- golden ---\n%s\n--- go ---\n%s", a, b)
	}
}

func TestWSAttachControlOutput(t *testing.T) {
	ts, mgr, _ := wsServer(t)
	ep := terminal.EndpointRef{ID: "test-server", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	sess, _ := mgr.Create(context.Background(), ep, "acc", terminal.Trigger{Kind: terminal.SourceUI})

	c := dialWS(t, ts)
	readMsg(t, c) // initial sessions:changed

	writeMsg(t, c, map[string]any{"type": "terminal:attach", "sessionId": sess.SessionID})
	// attach reply: status, then mode (control for UI source).
	if m := readMsg(t, c); m["type"] != "terminal:status" || m["status"] != "open" {
		t.Fatalf("expected status open, got %v", m)
	}
	if m := readMsg(t, c); m["type"] != "terminal:mode" || m["mode"] != "control" {
		t.Fatalf("expected control mode, got %v", m)
	}

	// Input (we have control via UI auto-control) is echoed by the mock.
	writeMsg(t, c, map[string]any{"type": "terminal:input", "sessionId": sess.SessionID, "data": "hi"})
	m := readMsg(t, c)
	if m["type"] != "terminal:output" || !strings.Contains(m["data"].(string), "hi") {
		t.Fatalf("expected output echo, got %v", m)
	}

	// Release control, then input must error.
	writeMsg(t, c, map[string]any{"type": "terminal:release-control", "sessionId": sess.SessionID})
	if m := readMsg(t, c); m["type"] != "terminal:mode" || m["mode"] != "observer" {
		t.Fatalf("expected observer mode, got %v", m)
	}
	writeMsg(t, c, map[string]any{"type": "terminal:input", "sessionId": sess.SessionID, "data": "x"})
	if m := readMsg(t, c); m["type"] != "error" {
		t.Fatalf("input without control must error, got %v", m)
	}
}

func TestWSAttachUnownedErrors(t *testing.T) {
	ts, mgr, _ := wsServer(t)
	// Session owned by a DIFFERENT account.
	ep := terminal.EndpointRef{ID: "e1", AccountID: "other", Host: "h", Port: 22, Username: "u"}
	sess, _ := mgr.Create(context.Background(), ep, "other", terminal.Trigger{Kind: terminal.SourceUI})

	c := dialWS(t, ts)
	readMsg(t, c) // initial sessions:changed (empty for acc)
	writeMsg(t, c, map[string]any{"type": "terminal:attach", "sessionId": sess.SessionID})
	if m := readMsg(t, c); m["type"] != "error" {
		t.Fatalf("cross-account attach must error, got %v", m)
	}
}
