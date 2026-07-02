// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// MCP surface parity (Phase 4 slice 1): the mcp-* goldens driven through the
// official go-sdk client against the /mcp streamable-HTTP handler, over a
// mock-transport session. The tool result is captured as {tool, isError,
// result|message} exactly as golden-mcp.test.ts does.
package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/golden"
	"github.com/rado0x54/shellwatch/internal/mcp"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

const mcpSeedPort = int64(49871)

func mcpServer(t *testing.T) *httptest.Server {
	t.Helper()
	db, err := store.Open("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	acc := "test-account-00000000-0000-0000-0000-000000000000"
	ctx := context.Background()
	db.ExecContext(ctx, `INSERT INTO accounts (id,name,max_sessions,created_at,updated_at) VALUES (?,'A',5,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, acc)
	db.ExecContext(ctx, `INSERT INTO endpoints (id,account_id,label,host,port,username,user_verification,agent_forward,enabled,created_at,updated_at) VALUES ('test-server',?,'Test Server','127.0.0.1',?,'testuser','required',1,1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, acc, mcpSeedPort)
	db.ExecContext(ctx, `INSERT INTO ssh_keys (id,label,type,public_key,fingerprint,enabled,created_at,updated_at) VALUES ('test-key','Test Key','file','ssh-ed25519 AAAA','SHA256:abcdef',1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)

	mock := terminal.NewMockTransport()
	mgr := terminal.NewManager(
		func(context.Context, terminal.FactoryParams) (terminal.Transport, error) { return mock, nil },
		clock.Real{}, 0)

	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	resolve := auth.Resolver(func(_ context.Context, tok string) *auth.Principal {
		if tok == "mcp" {
			return &auth.Principal{AccountID: acc, Scopes: []string{"mcp"}}
		}
		return nil
	})
	handler := New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
		MCP: &mcp.Deps{
			AgentDeps: agent.Deps{Manager: mgr, Endpoints: store.NewEndpoints(db, clock.Real{}), Demo: demo.NewService(nil)},
			Keys:      store.NewSSHKeys(db),
		},
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

// mcpConnect dials the /mcp endpoint with a bearer token via the official
// client (the go-sdk transport sends Authorization on each request).
func mcpConnect(t *testing.T, ts *httptest.Server) *mcpsdk.ClientSession {
	t.Helper()
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test", Version: "1"}, nil)
	httpClient := &http.Client{Transport: bearerRT{tok: "mcp", base: http.DefaultTransport}}
	transport := &mcpsdk.StreamableClientTransport{
		Endpoint:   ts.URL + "/mcp",
		HTTPClient: httpClient,
	}
	sess, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("mcp connect: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

type bearerRT struct {
	tok  string
	base http.RoundTripper
}

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return b.base.RoundTrip(r)
}

// callTool returns the single text content block + isError, matching the Node
// harness's capture.
func callTool(t *testing.T, sess *mcpsdk.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := sess.CallTool(context.Background(), &mcpsdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if len(res.Content) == 0 {
		t.Fatalf("call %s: no content", name)
	}
	text := res.Content[0].(*mcpsdk.TextContent).Text
	return text, res.IsError
}

func assertToolGolden(t *testing.T, name, tool string, sess *mcpsdk.ClientSession, args map[string]any) {
	t.Helper()
	text, isErr := callTool(t, sess, tool, args)
	var envelope map[string]any
	if isErr {
		envelope = map[string]any{"tool": tool, "isError": true, "message": text}
	} else {
		var result any
		if err := json.Unmarshal([]byte(text), &result); err != nil {
			t.Fatalf("%s: result not JSON: %v (%q)", tool, err, text)
		}
		envelope = map[string]any{"tool": tool, "isError": false, "result": result}
	}
	got := golden.Normalize(envelope, golden.Options{Ports: []float64{float64(mcpSeedPort)}})
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

func TestMCPToolGoldens(t *testing.T) {
	ts := mcpServer(t)
	sess := mcpConnect(t, ts)

	assertToolGolden(t, "mcp-endpoints-list", "shellwatch_manage_endpoints", sess, map[string]any{"action": "list"})
	assertToolGolden(t, "mcp-endpoints-read", "shellwatch_manage_endpoints", sess, map[string]any{"action": "read", "id": "test-server"})
	assertToolGolden(t, "mcp-endpoints-read-missing", "shellwatch_manage_endpoints", sess, map[string]any{"action": "read", "id": "nope"})
	assertToolGolden(t, "mcp-keys-list", "shellwatch_manage_keys", sess, map[string]any{"action": "list"})

	// Session lifecycle: create -> list -> send_keys -> close.
	assertToolGolden(t, "mcp-create-session", "shellwatch_create_session", sess,
		map[string]any{"endpointId": "test-server", "reason": "golden capture"})
	assertToolGolden(t, "mcp-list-sessions", "shellwatch_list_sessions", sess, map[string]any{})
	// send_keys / close need the created session id; list to fetch it.
	text, _ := callTool(t, sess, "shellwatch_list_sessions", map[string]any{})
	var listed struct {
		Sessions []struct {
			SessionID string `json:"sessionId"`
		} `json:"sessions"`
	}
	_ = json.Unmarshal([]byte(text), &listed)
	if len(listed.Sessions) == 0 {
		t.Fatal("no session created")
	}
	sid := listed.Sessions[0].SessionID
	assertToolGolden(t, "mcp-send-keys", "shellwatch_send_keys", sess,
		map[string]any{"sessionId": sid, "keys": []string{"text:echo hi", "enter"}})
	assertToolGolden(t, "mcp-close-session", "shellwatch_close_session", sess, map[string]any{"sessionId": sid})
}
