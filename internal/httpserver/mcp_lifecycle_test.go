// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// MCP stateless dual-era behaviour (#243): no protocol-level sessions
// (GET/DELETE 405, no Mcp-Session-Id), per-(account, OAuth client) terminal
// session ownership with cross-client/cross-account isolation, legacy
// (initialize) and modern (server/discover) clients on the same handler,
// resources/updated over subscriptions/listen, and read_output long-polling.
package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/endpointsvc"
	"github.com/rado0x54/shellwatch/internal/mcp"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// mcpLifecycleServer is like mcpServer but with several principals (two OAuth
// clients on account A, one on account B) and the terminal manager exposed.
func mcpLifecycleServer(t *testing.T) (*httptest.Server, *terminal.Manager) {
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
	principals := map[string]auth.Principal{
		"tok-a1": {AccountID: "acc-a", ClientID: "client-1", Scopes: []string{"mcp"}},
		"tok-a2": {AccountID: "acc-a", ClientID: "client-2", Scopes: []string{"mcp"}},
		"tok-b1": {AccountID: "acc-b", ClientID: "client-1", Scopes: []string{"mcp"}},
	}
	resolve := auth.Resolver(func(_ context.Context, tok string) *auth.Principal {
		if p, ok := principals[tok]; ok {
			return &p
		}
		return nil
	})
	handler := New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
		MCP: &mcp.Deps{
			AgentDeps:      agent.Deps{Manager: mgr, Svc: &endpointsvc.Service{Endpoints: store.NewEndpoints(db, clock.Real{}), Demo: demo.NewService(nil)}},
			Keys:           store.NewSSHKeys(db),
			NotifyDebounce: 20 * time.Millisecond,
		},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts, mgr
}

// mcpConnectVer dials /mcp as token at the given protocol version ("" =
// latest, i.e. 2026-07-28 via server/discover).
func mcpConnectVer(t *testing.T, ts *httptest.Server, token, version string, opts *mcpsdk.ClientOptions) *mcpsdk.ClientSession {
	t.Helper()
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test", Version: "1"}, opts)
	httpClient := &http.Client{Transport: bearerRT{tok: token, base: http.DefaultTransport}}
	var sessOpts *mcpsdk.ClientSessionOptions
	if version != "" {
		sessOpts = &mcpsdk.ClientSessionOptions{ProtocolVersion: version}
	}
	sess, err := client.Connect(context.Background(), &mcpsdk.StreamableClientTransport{
		Endpoint: ts.URL + "/mcp", HTTPClient: httpClient,
	}, sessOpts)
	if err != nil {
		t.Fatalf("mcp connect (%s, %q): %v", token, version, err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

func createTerminalSession(t *testing.T, sess *mcpsdk.ClientSession, endpointID string) string {
	t.Helper()
	text, isErr := callTool(t, sess, "shellwatch_create_session",
		map[string]any{"endpointId": endpointID, "reason": "lifecycle test"})
	if isErr {
		t.Fatalf("create_session: %s", text)
	}
	var created struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal([]byte(text), &created); err != nil || created.SessionID == "" {
		t.Fatalf("create_session result: %q (%v)", text, err)
	}
	return created.SessionID
}

// The stateless transport mints no sessions: GET and DELETE answer 405, and no
// response ever carries an Mcp-Session-Id.
func TestMCPStatelessTransport(t *testing.T) {
	ts, _ := mcpLifecycleServer(t)

	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		req, _ := http.NewRequest(method, ts.URL+"/mcp", nil)
		req.Header.Set("Authorization", "Bearer tok-a1")
		req.Header.Set("Accept", "application/json, text/event-stream")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s /mcp: got %d, want 405", method, res.StatusCode)
		}
		if allow := res.Header.Get("Allow"); allow != "POST" {
			t.Errorf("%s /mcp Allow: got %q, want POST", method, allow)
		}
	}

	// A legacy initialize is answered, but no session id is minted.
	res := rawMCPPost(t, ts, "tok-a1", "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"legacy","version":"1"}}}`)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("initialize: status %d (%s)", res.StatusCode, body)
	}
	if sid := res.Header.Get("Mcp-Session-Id"); sid != "" {
		t.Errorf("initialize minted an Mcp-Session-Id (%q); stateless servers must not", sid)
	}
}

// rawMCPPost drives /mcp without the go-sdk client (legacy era: no required
// Mcp-* headers).
func rawMCPPost(t *testing.T, ts *httptest.Server, token, protocolVersion, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if protocolVersion != "" {
		req.Header.Set("Mcp-Protocol-Version", protocolVersion)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// Ownership is (account, OAuth client): another client on the same account and
// the same client id on another account both get the uniform "session not
// found"; the owner keeps access across connections (no MCP session to lose).
func TestMCPCrossClientIsolation(t *testing.T) {
	ts, _ := mcpLifecycleServer(t)
	owner := mcpConnectVer(t, ts, "tok-a1", "", nil)
	sid := createTerminalSession(t, owner, "ep-a")

	for _, tok := range []string{"tok-a2", "tok-b1"} {
		foreign := mcpConnectVer(t, ts, tok, "", nil)
		text, _ := callTool(t, foreign, "shellwatch_list_sessions", map[string]any{})
		if strings.Contains(text, sid) {
			t.Errorf("%s sees foreign session in list: %s", tok, text)
		}
		text, isErr := callTool(t, foreign, "shellwatch_read_output", map[string]any{"sessionId": sid})
		if !isErr || !strings.Contains(text, "session not found") {
			t.Errorf("%s read_output on foreign session: isErr=%v %q", tok, isErr, text)
		}
		text, isErr = callTool(t, foreign, "shellwatch_close_session", map[string]any{"sessionId": sid})
		if !isErr || !strings.Contains(text, "session not found") {
			t.Errorf("%s close_session on foreign session: isErr=%v %q", tok, isErr, text)
		}
	}

	// The owning client reconnects (fresh ClientSession, same token): the
	// terminal session is still its to use — ownership survives connections.
	again := mcpConnectVer(t, ts, "tok-a1", "", nil)
	text, _ := callTool(t, again, "shellwatch_list_sessions", map[string]any{})
	if !strings.Contains(text, sid) {
		t.Fatalf("owner lost its session across connections: %s", text)
	}
	if text, isErr := callTool(t, again, "shellwatch_close_session", map[string]any{"sessionId": sid}); isErr {
		t.Fatalf("owner close after reconnect: %s", text)
	}
}

// A legacy (2025-06-18, initialize handshake) client works on the same
// stateless handler and still receives the live-endpoint instructions.
func TestMCPLegacyEraWorks(t *testing.T) {
	ts, _ := mcpLifecycleServer(t)
	sess := mcpConnectVer(t, ts, "tok-a1", "2025-06-18", nil)

	res := sess.InitializeResult()
	if res == nil {
		t.Fatal("no initialize result")
	}
	for _, want := range []string{
		"ShellWatch is an SSH session broker",
		"- ep-a: Box A (u@127.0.0.1:22)",
		"shellwatch_create_session",
		"waitMs",
		"sudo:",
	} {
		if !strings.Contains(res.Instructions, want) {
			t.Errorf("instructions missing %q\n%s", want, res.Instructions)
		}
	}

	sid := createTerminalSession(t, sess, "ep-a")
	if text, isErr := callTool(t, sess, "shellwatch_send_keys",
		map[string]any{"sessionId": sid, "keys": []string{"text:hi"}}); isErr {
		t.Fatalf("send_keys: %s", text)
	}
	if text, isErr := callTool(t, sess, "shellwatch_close_session", map[string]any{"sessionId": sid}); isErr {
		t.Fatalf("close: %s", text)
	}
}

// Era interop: a modern and a legacy connection with the same token operate on
// the same terminal sessions.
func TestMCPEraInterop(t *testing.T) {
	ts, _ := mcpLifecycleServer(t)
	modern := mcpConnectVer(t, ts, "tok-a1", "", nil)
	legacy := mcpConnectVer(t, ts, "tok-a1", "2025-11-25", nil)

	sid := createTerminalSession(t, modern, "ep-a")
	text, _ := callTool(t, legacy, "shellwatch_list_sessions", map[string]any{})
	if !strings.Contains(text, sid) {
		t.Fatalf("legacy connection of the same client should see the session: %s", text)
	}
	if text, isErr := callTool(t, legacy, "shellwatch_close_session", map[string]any{"sessionId": sid}); isErr {
		t.Fatalf("legacy close: %s", text)
	}
}

// shellwatch://sessions resources: readable by the owner, uniform not-found
// for foreign clients, and resources/updated delivered over
// subscriptions/listen on output and status changes.
func TestMCPSessionResources(t *testing.T) {
	ts, _ := mcpLifecycleServer(t)

	var mu sync.Mutex
	var updated []string
	owner := mcpConnectVer(t, ts, "tok-a1", "", &mcpsdk.ClientOptions{
		ResourceUpdatedHandler: func(_ context.Context, req *mcpsdk.ResourceUpdatedNotificationRequest) {
			mu.Lock()
			updated = append(updated, req.Params.URI)
			mu.Unlock()
		},
	})
	sid := createTerminalSession(t, owner, "ep-a")
	uri := "shellwatch://sessions/" + sid
	ctx := context.Background()

	// Read the session document and the list.
	res, err := owner.ReadResource(ctx, &mcpsdk.ReadResourceParams{URI: uri})
	if err != nil {
		t.Fatalf("read session resource: %v", err)
	}
	var doc struct {
		SessionID string `json:"sessionId"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &doc); err != nil || doc.SessionID != sid || doc.Status != "open" {
		t.Fatalf("session doc: %q (%v)", res.Contents[0].Text, err)
	}
	listRes, err := owner.ReadResource(ctx, &mcpsdk.ReadResourceParams{URI: "shellwatch://sessions"})
	if err != nil || !strings.Contains(listRes.Contents[0].Text, sid) {
		t.Fatalf("sessions list resource: %v %+v", err, listRes)
	}

	// Foreign client: uniform not-found on read; a subscribe attempt is
	// rejected server-side (the sdk client fires listen asynchronously, so the
	// rejection is observable only as silence — asserted at the end).
	var foreignMu sync.Mutex
	foreignUpdates := 0
	foreign := mcpConnectVer(t, ts, "tok-a2", "", &mcpsdk.ClientOptions{
		ResourceUpdatedHandler: func(context.Context, *mcpsdk.ResourceUpdatedNotificationRequest) {
			foreignMu.Lock()
			foreignUpdates++
			foreignMu.Unlock()
		},
	})
	if _, err := foreign.ReadResource(ctx, &mcpsdk.ReadResourceParams{URI: uri}); err == nil {
		t.Error("foreign client could read the session resource")
	}
	_ = foreign.Subscribe(ctx, &mcpsdk.SubscribeParams{URI: uri})

	// Owner subscribes, then output triggers resources/updated (debounced).
	// Subscribe's listen stream registers asynchronously, so keep nudging
	// output until the first notification lands.
	if err := owner.Subscribe(ctx, &mcpsdk.SubscribeParams{URI: uri}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if text, isErr := callTool(t, owner, "shellwatch_send_keys",
			map[string]any{"sessionId": sid, "keys": []string{"text:ping"}}); isErr {
			t.Fatalf("send_keys: %s", text)
		}
		mu.Lock()
		n := len(updated)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	got := append([]string(nil), updated...)
	mu.Unlock()
	if len(got) == 0 {
		t.Fatal("no resources/updated arrived for owned session output")
	}
	for _, u := range got {
		if u != uri {
			t.Errorf("unexpected updated uri %q", u)
		}
	}
	foreignMu.Lock()
	defer foreignMu.Unlock()
	if foreignUpdates != 0 {
		t.Errorf("foreign client received %d resources/updated for a session it does not own", foreignUpdates)
	}
}

// read_output waitMs long-polls: it returns early when output arrives and at
// the deadline (empty) when none does.
func TestMCPReadOutputWait(t *testing.T) {
	ts, _ := mcpLifecycleServer(t)
	sess := mcpConnectVer(t, ts, "tok-a1", "", nil)
	sid := createTerminalSession(t, sess, "ep-a")

	// No output yet: a short wait returns empty at the deadline.
	start := time.Now()
	text, isErr := callTool(t, sess, "shellwatch_read_output",
		map[string]any{"sessionId": sid, "waitMs": 300})
	if isErr {
		t.Fatalf("read_output wait: %s", text)
	}
	var out struct {
		Data   string `json:"data"`
		Offset int64  `json:"offset"`
	}
	_ = json.Unmarshal([]byte(text), &out)
	if out.Data != "" {
		t.Fatalf("expected no data, got %q", out.Data)
	}
	if time.Since(start) < 250*time.Millisecond {
		t.Fatalf("wait returned too early: %v", time.Since(start))
	}

	// Output arriving mid-wait wakes the poll before the deadline.
	go func() {
		time.Sleep(200 * time.Millisecond)
		_, _ = callTool(t, sess, "shellwatch_send_keys",
			map[string]any{"sessionId": sid, "keys": []string{"text:hello"}})
	}()
	start = time.Now()
	text, isErr = callTool(t, sess, "shellwatch_read_output",
		map[string]any{"sessionId": sid, "afterOffset": out.Offset, "waitMs": 10000})
	if isErr {
		t.Fatalf("read_output long poll: %s", text)
	}
	_ = json.Unmarshal([]byte(text), &out)
	if out.Data != "hello" {
		t.Fatalf("long poll data: %q", out.Data)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("long poll did not return early: %v", elapsed)
	}

	if text, isErr := callTool(t, sess, "shellwatch_read_output",
		map[string]any{"sessionId": sid, "waitMs": 30001}); !isErr || !strings.Contains(text, "waitMs") {
		t.Errorf("waitMs over cap accepted: %q", text)
	}
}

// Version negotiation edges: an unsupported Mcp-Protocol-Version header is a
// 400, and a header-less legacy request (treated as the pre-2025-06-18 era,
// which this server dropped) is still answered by the legacy handshake rules
// rather than rejected outright — documented in docs/api/mcp-tools.md.
func TestMCPProtocolVersionEdges(t *testing.T) {
	ts, _ := mcpLifecycleServer(t)

	res := rawMCPPost(t, ts, "tok-a1", "2025-03-26", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "Unsupported protocol version") {
		t.Errorf("excluded version header: got %d %q, want 400 with supported list", res.StatusCode, body)
	}

	// Supported legacy version in the header works without initialize (the
	// stateless handler default-initializes the temporary session).
	res = rawMCPPost(t, ts, "tok-a1", "2025-06-18", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	body, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "shellwatch_create_session") {
		t.Errorf("legacy tools/list: got %d %q", res.StatusCode, body)
	}
}

// Consent revocation closes exactly the revoked client's live MCP sessions
// (the REST hook calls CloseAllForClient; asserted here at the manager level).
func TestCloseAllForClient(t *testing.T) {
	ts, mgr := mcpLifecycleServer(t)
	a1 := mcpConnectVer(t, ts, "tok-a1", "", nil)
	a2 := mcpConnectVer(t, ts, "tok-a2", "", nil)
	sid1 := createTerminalSession(t, a1, "ep-a")
	sid2 := createTerminalSession(t, a2, "ep-a")

	if n := mgr.CloseAllForClient("acc-a", "client-1", terminal.CloseAgentDisconnect); n != 1 {
		t.Fatalf("CloseAllForClient client-1: closed %d, want 1", n)
	}
	waitForManagerRemoval(t, mgr, sid1)
	if s := mgr.GetSession(sid2); s == nil || s.Status != terminal.StatusOpen {
		t.Fatalf("client-2's session was collateral damage: %+v", s)
	}

	// Revoke-all ("" client) closes the account's remaining MCP sessions.
	if n := mgr.CloseAllForClient("acc-a", "", terminal.CloseAgentDisconnect); n != 1 {
		t.Fatalf("CloseAllForClient all: closed %d, want 1", n)
	}
	waitForManagerRemoval(t, mgr, sid2)
}

// waitForManagerRemoval waits until the manager forgot the session (an
// explicit Close removes it from the registry once the pump drained).
func waitForManagerRemoval(t *testing.T, mgr *terminal.Manager, id string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if mgr.GetSession(id) == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("session %s never removed", id)
}
