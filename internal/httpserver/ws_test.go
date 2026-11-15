// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// WebSocket hub parity (Phase 3 slice 4): the ws-sessions-changed golden plus
// attach/control/output behavior, driven by a real coder/websocket client
// through the hub against a mock-transport session.
package httpserver

import (
	"context"
	"encoding/json"
	"errors"
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
	ts, mgr := wsServerWithFactory(t,
		func(context.Context, terminal.FactoryParams) (terminal.Transport, error) { return mock, nil })
	return ts, mgr, mock
}

func wsServerWithFactory(t *testing.T, factory terminal.TransportFactory) (*httptest.Server, *terminal.Manager) {
	t.Helper()
	mgr := terminal.NewManager(factory, clock.Real{}, 0)
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
	return ts, mgr
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

	assertWSGolden(t, "ws-sessions-changed", msg)
}

// assertWSGolden compares a raw WS message (no envelope) to a golden, folding
// sessionId to sess_<ID>.
func assertWSGolden(t *testing.T, name string, msg map[string]any) {
	t.Helper()
	got := golden.Normalize(msg, golden.Options{})
	raw, _ := os.ReadFile(filepath.Join(goldensDir, name+".json"))
	var expected any
	_ = json.Unmarshal(raw, &expected)
	if !reflect.DeepEqual(got, expected) {
		a, _ := json.MarshalIndent(expected, "", "  ")
		b, _ := json.MarshalIndent(got, "", "  ")
		t.Errorf("%s mismatch\n--- golden ---\n%s\n--- go ---\n%s", name, a, b)
	}
}

func TestWSAttachControlOutput(t *testing.T) {
	ts, mgr, _ := wsServer(t)
	ep := terminal.EndpointRef{ID: "test-server", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	sess, _ := mgr.Create(context.Background(), ep, "acc", terminal.Trigger{Kind: terminal.SourceUI})

	c := dialWS(t, ts)
	readMsg(t, c) // initial sessions:changed

	writeMsg(t, c, map[string]any{"type": "terminal:attach", "sessionId": sess.SessionID})
	// attach reply: status, then mode (control for UI source) — pinned by the
	// ws-attach-status / ws-attach-mode goldens (sessionId folds to sess_<ID>).
	assertWSGolden(t, "ws-attach-status", readMsg(t, c))
	assertWSGolden(t, "ws-attach-mode", readMsg(t, c))

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

// An inbound /ws message over wshub.MaxInboundMessageBytes closes the link with
// 1009 (security review #7) rather than being buffered whole.
func TestWSRejectsOversizedInbound(t *testing.T) {
	ts, _, _ := wsServer(t)
	c := dialWS(t, ts)
	readMsg(t, c) // connect-time sessions list

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	big := `{"type":"terminal:input","sessionId":"x","data":"` + strings.Repeat("a", wshub.MaxInboundMessageBytes) + `"}`
	_ = c.Write(ctx, websocket.MessageText, []byte(big))
	for {
		_, _, err := c.Read(ctx)
		if err == nil {
			continue // drain anything queued before the close
		}
		if websocket.CloseStatus(err) != websocket.StatusMessageTooBig {
			t.Fatalf("read after oversized frame: err=%v, want close 1009", err)
		}
		return
	}
}

// A session still connecting (its factory blocked on human approval of the
// SSH signature) is listed to the browser as opening right away, and can be
// attached to before it opens (#273): approving from a toast navigates to
// /session/<id> while the connect is still in flight.
func TestWSListsOpeningSessionBeforeSetupCompletes(t *testing.T) {
	mock := terminal.NewMockTransport()
	t.Cleanup(func() { _ = mock.Close() })
	approve := make(chan struct{})
	ts, mgr := wsServerWithFactory(t, func(ctx context.Context, _ terminal.FactoryParams) (terminal.Transport, error) {
		select {
		case <-approve:
			return mock, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	c := dialWS(t, ts)
	if m := readMsg(t, c); len(m["sessions"].([]any)) != 0 {
		t.Fatalf("initial sessions:changed should be empty, got %v", m)
	}

	ep := terminal.EndpointRef{ID: "test-server", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	created := make(chan *terminal.Session, 1)
	go func() {
		sess, err := mgr.Create(context.Background(), ep, "acc", terminal.Trigger{Kind: terminal.SourceUI})
		if err != nil {
			t.Error(err)
		}
		created <- sess
	}()

	sessionStatus := func(m map[string]any) (id, status string) {
		t.Helper()
		list, _ := m["sessions"].([]any)
		if m["type"] != "sessions:changed" || len(list) != 1 {
			t.Fatalf("expected sessions:changed with one session, got %v", m)
		}
		entry := list[0].(map[string]any)
		return entry["sessionId"].(string), entry["status"].(string)
	}

	id, status := sessionStatus(readMsg(t, c))
	if status != string(terminal.StatusOpening) {
		t.Fatalf("status while connecting = %q, want opening", status)
	}

	writeMsg(t, c, map[string]any{"type": "terminal:attach", "sessionId": id})
	if m := readMsg(t, c); m["type"] != "terminal:status" || m["status"] != string(terminal.StatusOpening) {
		t.Fatalf("attach reply = %v, want terminal:status opening", m)
	}
	if m := readMsg(t, c); m["type"] != "terminal:mode" {
		t.Fatalf("attach reply = %v, want terminal:mode", m)
	}
	// The terminal sends its size right after attaching, while there is no
	// PTY yet (#273 review). Re-attaching afterwards is a sync point: the
	// connection handles frames in order, so its reply proves the resize
	// was processed before the setup completes.
	writeMsg(t, c, map[string]any{"type": "terminal:resize", "sessionId": id, "cols": 132, "rows": 43})
	writeMsg(t, c, map[string]any{"type": "terminal:attach", "sessionId": id})
	readMsg(t, c) // terminal:status
	readMsg(t, c) // terminal:mode

	close(approve)
	sess := <-created
	if sess == nil || sess.SessionID != id {
		t.Fatalf("created session %v, listed %q", sess, id)
	}
	if _, status := sessionStatus(readMsg(t, c)); status != string(terminal.StatusOpen) {
		t.Fatalf("status after setup = %q, want open", status)
	}
	if got := mock.Sizes(); len(got) != 1 || got[0] != [2]int{132, 43} {
		t.Fatalf("PTY sizes after open = %v, want the size sent while opening", got)
	}

	// The attach made while opening carries over: output reaches this client.
	writeMsg(t, c, map[string]any{"type": "terminal:input", "sessionId": id, "data": "hi"})
	if m := readMsg(t, c); m["type"] != "terminal:output" || !strings.Contains(m["data"].(string), "hi") {
		t.Fatalf("expected output echo, got %v", m)
	}
}

// A connect that fails during setup (e.g. the signature was denied) drops the
// opening row from the browser's list again, so a session page opened from
// the approval toast navigates away instead of showing a stale session (#273).
func TestWSOpeningSessionDroppedWhenSetupFails(t *testing.T) {
	deny := make(chan struct{})
	ts, mgr := wsServerWithFactory(t, func(ctx context.Context, _ terminal.FactoryParams) (terminal.Transport, error) {
		select {
		case <-deny:
			return nil, errors.New("signature denied")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	c := dialWS(t, ts)
	readMsg(t, c) // initial sessions:changed (empty)

	ep := terminal.EndpointRef{ID: "test-server", AccountID: "acc", Host: "h", Port: 22, Username: "u"}
	failed := make(chan error, 1)
	go func() {
		_, err := mgr.Create(context.Background(), ep, "acc", terminal.Trigger{Kind: terminal.SourceUI})
		failed <- err
	}()

	if m := readMsg(t, c); len(m["sessions"].([]any)) != 1 {
		t.Fatalf("expected the opening session listed, got %v", m)
	}
	close(deny)
	if err := <-failed; err == nil {
		t.Fatal("Create should fail when setup fails")
	}
	if m := readMsg(t, c); m["type"] != "sessions:changed" || len(m["sessions"].([]any)) != 0 {
		t.Fatalf("expected the failed session dropped from the list, got %v", m)
	}
}
