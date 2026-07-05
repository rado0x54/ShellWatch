// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// MCP session lifecycle security (H4/H5): cross-account Mcp-Session-Id replay
// gets the uniform Node-shaped 404, and closing the MCP session (client
// DELETE) destroys the AgentSession -> owned terminal sessions close with
// reason agent-disconnect.
package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/mcp"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// mcpLifecycleServer is like mcpServer but with two principals and the
// terminal manager exposed. sessionTimeout 0 = sessions never expire.
func mcpLifecycleServer(t *testing.T, sessionTimeout time.Duration) (*httptest.Server, *terminal.Manager) {
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
	db.ExecContext(ctx, `INSERT INTO accounts (id,name,max_sessions,created_at,updated_at) VALUES ('acc-a','A',5,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)
	db.ExecContext(ctx, `INSERT INTO accounts (id,name,max_sessions,created_at,updated_at) VALUES ('acc-b','B',5,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)
	db.ExecContext(ctx, `INSERT INTO endpoints (id,account_id,label,host,port,username,user_verification,agent_forward,enabled,created_at,updated_at) VALUES ('ep-a','acc-a','Box A','127.0.0.1',22,'u','required',1,1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)

	mgr := terminal.NewManager(
		func(context.Context, terminal.FactoryParams) (terminal.Transport, error) {
			return terminal.NewMockTransport(), nil
		}, clock.Real{}, 0)

	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	cfg.Security.AllowedNetworks = []string{"127.0.0.1/32", "::1/128"}
	resolve := auth.Resolver(func(_ context.Context, tok string) *auth.Principal {
		switch tok {
		case "tok-a":
			return &auth.Principal{AccountID: "acc-a", Scopes: []string{"mcp"}}
		case "tok-b":
			return &auth.Principal{AccountID: "acc-b", Scopes: []string{"mcp"}}
		}
		return nil
	})
	handler := New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
		MCP: &mcp.Deps{
			AgentDeps:      agent.Deps{Manager: mgr, Endpoints: store.NewEndpoints(db, clock.Real{}), Demo: demo.NewService(nil)},
			Keys:           store.NewSSHKeys(db),
			SessionTimeout: sessionTimeout,
		},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts, mgr
}

func mcpConnectAs(t *testing.T, ts *httptest.Server, token string) *mcpsdk.ClientSession {
	t.Helper()
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test", Version: "1"}, nil)
	httpClient := &http.Client{Transport: bearerRT{tok: token, base: http.DefaultTransport}}
	sess, err := client.Connect(context.Background(), &mcpsdk.StreamableClientTransport{
		Endpoint: ts.URL + "/mcp", HTTPClient: httpClient,
	}, nil)
	if err != nil {
		t.Fatalf("mcp connect: %v", err)
	}
	return sess
}

func TestMCPCrossAccountSessionIDIsUniform404(t *testing.T) {
	ts, _ := mcpLifecycleServer(t, 0)
	sessA := mcpConnectAs(t, ts, "tok-a")
	defer sessA.Close()
	sid := sessA.ID()
	if sid == "" {
		t.Fatal("no Mcp-Session-Id assigned")
	}

	// Replay account A's session id with account B's token.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer tok-b")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", sid)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("foreign session id: got %d, want 404", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	var rpc struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpc); err != nil {
		t.Fatalf("body not JSON-RPC: %q", body)
	}
	if rpc.Error.Code != -32001 || rpc.Error.Message != "Session not found" {
		t.Fatalf("wrong error envelope: %q", body)
	}

	// The rightful owner still works.
	if _, err := sessA.ListTools(context.Background(), nil); err != nil {
		t.Fatalf("owner's session broken after replay: %v", err)
	}

	// An unknown/stale id gets the SAME envelope — not go-sdk's plain-text 404.
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req2.Header.Set("Authorization", "Bearer tok-a")
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Accept", "application/json, text/event-stream")
	req2.Header.Set("Mcp-Session-Id", "00000000-0000-4000-8000-000000000000")
	res2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	body2, _ := io.ReadAll(res2.Body)
	if res2.StatusCode != http.StatusNotFound || !strings.Contains(string(body2), `"code":-32001`) {
		t.Fatalf("stale session id: got %d %q, want uniform JSON-RPC 404", res2.StatusCode, body2)
	}
}

func TestMCPDisconnectClosesOwnedSessions(t *testing.T) {
	ts, mgr := mcpLifecycleServer(t, 0)
	sess := mcpConnectAs(t, ts, "tok-a")

	res, err := sess.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      "shellwatch_create_session",
		Arguments: map[string]any{"endpointId": "ep-a", "reason": "lifecycle test"},
	})
	if err != nil || res.IsError {
		t.Fatalf("create_session failed: %v %+v", err, res)
	}
	if n := len(mgr.ListForAccount("acc-a")); n != 1 {
		t.Fatalf("expected 1 live session, got %d", n)
	}

	// Client-side Close sends the session DELETE; the server must destroy the
	// AgentSession and close its owned terminal sessions.
	if err := sess.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(mgr.ListForAccount("acc-a")) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("terminal session still alive after MCP disconnect: %+v", mgr.ListForAccount("acc-a"))
}

// rawMCPPost drives /mcp without the go-sdk client — the client keeps a
// hanging SSE GET open, which suspends the sdk's idle timer, so expiry can
// only be exercised with bare request/response POSTs.
func rawMCPPost(t *testing.T, ts *httptest.Server, token, sessionID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// A client that vanishes without DELETE must not leak: after SessionTimeout
// of no HTTP activity, the sdk session expires, the Wait teardown destroys
// the AgentSession (owned SSH sessions close with agent-disconnect), and the
// stale Mcp-Session-Id answers with the uniform 404.
func TestMCPIdleSessionExpiryClosesEverything(t *testing.T) {
	const timeout = 500 * time.Millisecond
	ts, mgr := mcpLifecycleServer(t, timeout)

	// initialize -> session id.
	res := rawMCPPost(t, ts, "tok-a", "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"vanisher","version":"1"}}}`)
	sid := res.Header.Get("Mcp-Session-Id")
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || sid == "" {
		t.Fatalf("initialize: status=%d sid=%q", res.StatusCode, sid)
	}

	res = rawMCPPost(t, ts, "tok-a", sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	io.Copy(io.Discard, res.Body)
	res.Body.Close()

	res = rawMCPPost(t, ts, "tok-a", sid,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shellwatch_create_session","arguments":{"endpointId":"ep-a","reason":"idle expiry test"}}}`)
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("create_session: status=%d", res.StatusCode)
	}
	if n := len(mgr.ListForAccount("acc-a")); n != 1 {
		t.Fatalf("expected 1 live terminal session, got %d", n)
	}

	// Vanish. No DELETE, no further requests. Everything must unwind.
	deadline := time.Now().Add(timeout + 5*time.Second)
	for time.Now().Before(deadline) {
		if len(mgr.ListForAccount("acc-a")) == 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if n := len(mgr.ListForAccount("acc-a")); n != 0 {
		t.Fatalf("terminal session still alive after MCP idle expiry: %d", n)
	}

	// The expired id is gone from the owners registry -> uniform JSON 404.
	res = rawMCPPost(t, ts, "tok-a", sid, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound || !strings.Contains(string(body), `"code":-32001`) {
		t.Fatalf("expired session id: got %d %q, want uniform JSON-RPC 404", res.StatusCode, body)
	}
}
