// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// File-transfer surfaces at the router level (#263): the link route's gating
// (IP allowlist, no bearer token, no-store, token redaction in the access
// log), the MCP file tools' ownership and path rules, the terminal:file
// frames with the attach snapshot, and the audit endpoint's golden. The
// streaming semantics themselves are covered against a real SFTP server in
// internal/transfer.
package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/audit"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/buildinfo"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/endpointsvc"
	"github.com/rado0x54/shellwatch/internal/mcp"
	"github.com/rado0x54/shellwatch/internal/rest"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
	"github.com/rado0x54/shellwatch/internal/transfer"
	wshub "github.com/rado0x54/shellwatch/internal/ws"
)

type transferRig struct {
	ts  *httptest.Server
	mgr *terminal.Manager
	svc *transfer.Service
	hub *wshub.Hub
}

// transferServer mounts /mcp (with the file tools), /ws, the link route and
// the audit endpoint over mock-transport sessions.
func transferServer(t *testing.T, allowedNetworks []string) *transferRig {
	t.Helper()
	db, err := store.Open("sqlite:" + t.TempDir() + "/transfers.db")
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
	hub := wshub.NewHub(mgr)
	t.Cleanup(hub.Close)
	fileLog := audit.NewFileTransfers(db, clock.Real{})
	svc := transfer.New(transfer.Params{
		Manager: mgr, Audit: fileLog, Publisher: hub,
		ExternalURL: func() string { return externalURL },
	})
	t.Cleanup(svc.Close)
	hub.SetFileSnapshot(svc.SnapshotTo)

	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	cfg.Security.AllowedNetworks = allowedNetworks
	principals := map[string]auth.Principal{
		"tok-a1": {AccountID: "acc-a", ClientID: "client-1", Scopes: []string{"mcp"}},
		"tok-a2": {AccountID: "acc-a", ClientID: "client-2", Scopes: []string{"mcp"}},
		"ui":     {AccountID: "acc-a", Scopes: []string{"ui"}},
		"ui-b":   {AccountID: "acc-b", Scopes: []string{"ui"}},
	}
	resolve := auth.Resolver(func(_ context.Context, tok string) *auth.Principal {
		if p, ok := principals[tok]; ok {
			return &p
		}
		return nil
	})
	handler := New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
		WSHub: hub,
		MCP: &mcp.Deps{
			AgentDeps: agent.Deps{Manager: mgr, Svc: &endpointsvc.Service{Endpoints: store.NewEndpoints(db, clock.Real{}), Demo: demo.NewService(nil)}},
			Keys:      store.NewSSHKeys(db),
			Transfers: svc,
		},
		Audit:     &rest.Audit{Sessions: audit.NewSessions(db), Signings: audit.NewSignings(db), FileTransfers: fileLog},
		Transfers: svc,
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return &transferRig{ts: ts, mgr: mgr, svc: svc, hub: hub}
}

var loopbackOnly = []string{"127.0.0.1/32", "::1/128"}

func rawRequest(t *testing.T, method, url, bearer string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader("payload"))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res, strings.TrimSpace(string(body))
}

// The link route needs no bearer token (the path token is the credential),
// answers the uniform 404 for anything it does not recognize, and never lets
// a response be cached.
func TestTransferLinkRouteUniform404(t *testing.T) {
	rig := transferServer(t, loopbackOnly)
	for _, method := range []string{http.MethodPut, http.MethodGet, http.MethodPost, http.MethodDelete} {
		res, body := rawRequest(t, method, rig.ts.URL+"/api/transfers/not-a-real-token", "")
		if res.StatusCode != http.StatusNotFound || body != `{"error":"Not found"}` {
			t.Errorf("%s unknown token: %d %s", method, res.StatusCode, body)
		}
		if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s Cache-Control = %q, want no-store", method, cc)
		}
	}
}

// A non-allowlisted peer gets exactly what it gets from /mcp.
func TestTransferLinkRouteIPAllowlist(t *testing.T) {
	rig := transferServer(t, []string{"10.99.0.0/16"}) // httptest's 127.0.0.1 is outside
	link, linkBody := rawRequest(t, http.MethodPut, rig.ts.URL+"/api/transfers/any-token", "")
	mcpRes, mcpBody := rawRequest(t, http.MethodPost, rig.ts.URL+"/mcp", "tok-a1")
	if link.StatusCode != http.StatusForbidden || mcpRes.StatusCode != http.StatusForbidden {
		t.Fatalf("status: link %d, mcp %d, want 403/403", link.StatusCode, mcpRes.StatusCode)
	}
	if linkBody != mcpBody {
		t.Errorf("bodies differ: link %q vs mcp %q", linkBody, mcpBody)
	}
}

// The access log never carries a transfer token.
func TestTransferTokenRedactedInAccessLog(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	rig := transferServer(t, loopbackOnly)
	const token = "s3cr3t-transfer-token-value"
	rawRequest(t, http.MethodPut, rig.ts.URL+"/api/transfers/"+token, "")
	logged := buf.String()
	if strings.Contains(logged, token) {
		t.Errorf("token leaked into the access log:\n%s", logged)
	}
	if !strings.Contains(logged, "path=/api/transfers/***") {
		t.Errorf("redacted path missing from the access log:\n%s", logged)
	}
	if got := redactPath("/api/endpoints/abc"); got != "/api/endpoints/abc" {
		t.Errorf("unrelated path altered: %s", got)
	}
}

func TestMCPFileTools(t *testing.T) {
	rig := transferServer(t, loopbackOnly)
	owner := mcpConnectVer(t, rig.ts, "tok-a1", "", nil)
	other := mcpConnectVer(t, rig.ts, "tok-a2", "", nil)

	tools, err := owner.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range tools.Tools {
		names[tool.Name] = true
	}
	for _, want := range []string{"shellwatch_list_dir", "shellwatch_read_file", "shellwatch_write_file", "shellwatch_transfer_file"} {
		if !names[want] {
			t.Errorf("tool %s not registered", want)
		}
	}

	sid := createTerminalSession(t, owner, "ep-a")

	// Another OAuth client of the same account, and an unknown id, both get
	// the uniform error — on every file tool.
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"shellwatch_list_dir", map[string]any{"sessionId": sid, "path": "/etc"}},
		{"shellwatch_read_file", map[string]any{"sessionId": sid, "path": "/etc/hosts"}},
		{"shellwatch_write_file", map[string]any{"sessionId": sid, "path": "/tmp/x", "content": "x"}},
		{"shellwatch_transfer_file", map[string]any{"action": "create", "sessionId": sid, "direction": "upload", "path": "/tmp/x"}},
	} {
		text, isErr := callTool(t, other, tc.tool, tc.args)
		if !isErr || text != "session not found: "+sid {
			t.Errorf("%s as a foreign client: isError=%v %q", tc.tool, isErr, text)
		}
	}
	if text, isErr := callTool(t, owner, "shellwatch_read_file", map[string]any{"sessionId": "sess_000000000000", "path": "/etc/hosts"}); !isErr || text != "session not found: sess_000000000000" {
		t.Errorf("unknown session: %q", text)
	}

	// Relative paths are an isError naming the reason.
	if text, isErr := callTool(t, owner, "shellwatch_read_file", map[string]any{"sessionId": sid, "path": "notes.txt"}); !isErr ||
		!strings.Contains(text, "path must be absolute") {
		t.Errorf("relative path: isError=%v %q", isErr, text)
	}
	// setuid / decimal-digit modes are refused before anything is opened.
	for _, mode := range []any{644, "4755", 0o4755} {
		if text, isErr := callTool(t, owner, "shellwatch_write_file", map[string]any{"sessionId": sid, "path": "/tmp/x", "content": "x", "mode": mode}); !isErr ||
			!strings.Contains(text, "mode must be permission bits") {
			t.Errorf("mode %v: isError=%v %q", mode, isErr, text)
		}
	}
	// A transport without the file capability (the mock) says so.
	if text, isErr := callTool(t, owner, "shellwatch_list_dir", map[string]any{"sessionId": sid, "path": "/etc"}); !isErr ||
		!strings.Contains(text, "does not support file transfer") {
		t.Errorf("mock transport: isError=%v %q", isErr, text)
	}
	// Unknown transfer ids are uniform too.
	for _, action := range []string{"status", "cancel"} {
		if text, isErr := callTool(t, owner, "shellwatch_transfer_file", map[string]any{"action": action, "transferId": "xfer_0000000000000000"}); !isErr ||
			text != "transfer not found: xfer_0000000000000000" {
			t.Errorf("%s of an unknown transfer: %q", action, text)
		}
	}

	// The failed inline call above was audited, account-scoped.
	_, page := doJSON(t, rig.ts, "GET", "/api/audit/file-transfers?sessionId="+sid, "")
	rows, _ := page["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("audit rows for the session: %+v", page)
	}
	row := rows[0].(map[string]any)
	if row["tier"] != "inline" || row["direction"] != "list" || row["status"] != "failed" || row["clientId"] != "client-1" || row["path"] != "/etc" {
		t.Errorf("audit row: %+v", row)
	}
	req, _ := http.NewRequest("GET", rig.ts.URL+"/api/audit/file-transfers", nil)
	req.Header.Set("Authorization", "Bearer ui-b")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var foreign map[string]any
	json.NewDecoder(res.Body).Decode(&foreign)
	res.Body.Close()
	if rows, _ := foreign["rows"].([]any); len(rows) != 0 {
		t.Errorf("another account sees the rows: %+v", foreign)
	}
	_ = mcpsdk.CallToolParams{}
}

// terminal:file frames reach connections attached to the session, and the
// attach reply carries a frame per unfinished transfer.
func TestWSFileFramesAndAttachSnapshot(t *testing.T) {
	rig := transferServer(t, loopbackOnly)
	ep := terminal.EndpointRef{ID: "ep-a", AccountID: "acc-a", Host: "h", Port: 22, Username: "u"}
	sess, err := rig.mgr.Create(context.Background(), ep, "acc-a", terminal.Trigger{Kind: terminal.SourceMCP, OwnerClientID: "client-1"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := map[string]any{
		"type": "terminal:file", "sessionId": sess.SessionID, "transferId": "xfer_snapshot",
		"direction": "upload", "path": "/srv/backup.tgz", "bytes": 1024, "totalBytes": 4096,
		"status": "active", "tier": "link", "mcpClientName": "agent",
	}
	rig.hub.SetFileSnapshot(func(id string, deliver func([]any)) {
		if id == sess.SessionID {
			deliver([]any{snapshot})
		}
	})

	c := dialWS(t, rig.ts)
	readMsg(t, c) // connect-time sessions:changed
	// Not attached yet: a frame for the session must not arrive.
	rig.hub.SendToSession(sess.SessionID, map[string]any{"type": "terminal:file", "transferId": "xfer_before_attach", "sessionId": sess.SessionID})

	writeMsg(t, c, map[string]any{"type": "terminal:attach", "sessionId": sess.SessionID})
	if m := readMsg(t, c); m["type"] != "terminal:status" {
		t.Fatalf("frame 1: %+v", m)
	}
	if m := readMsg(t, c); m["type"] != "terminal:mode" {
		t.Fatalf("frame 2: %+v", m)
	}
	snap := readMsg(t, c)
	if snap["type"] != "terminal:file" || snap["transferId"] != "xfer_snapshot" || snap["status"] != "active" || snap["totalBytes"] != float64(4096) {
		t.Fatalf("attach snapshot frame: %+v", snap)
	}

	rig.hub.SendToSession(sess.SessionID, map[string]any{
		"type": "terminal:file", "sessionId": sess.SessionID, "transferId": "xfer_live", "status": "completed",
	})
	if m := readMsg(t, c); m["type"] != "terminal:file" || m["transferId"] != "xfer_live" {
		t.Fatalf("live frame: %+v", m)
	}
}

func TestAuditFileTransfersGolden(t *testing.T) {
	db, err := store.Open("sqlite:" + t.TempDir() + "/golden.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	db.Exec(`INSERT INTO accounts (id,name,created_at,updated_at) VALUES (?,'Audit','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`, auditAccount)
	str := func(s string) *string { return &s }
	total, yes := int64(52428800), true
	log := audit.NewFileTransfers(db, clock.Real{})
	log.Save(audit.FileTransferRow{
		TransferID: "xfer_0000000000000001", AccountID: auditAccount, SessionID: "sess_000000000002", EndpointID: "audit-endpoint-2",
		Tier: "inline", Direction: "upload", Path: "/etc/nginx/nginx.conf", Status: "completed", Bytes: 2150,
		SHA256:   str("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
		ClientID: str("client-1"), MCPClientName: str("codex"), MCPClientVersion: str("1.2.3"), SourceIP: str("203.0.113.7"),
		CreatedAt: "2026-01-01T00:00:01.000Z", UpdatedAt: "2026-01-01T00:00:01.000Z", FinishedAt: str("2026-01-01T00:00:01.000Z"),
	})
	log.Save(audit.FileTransferRow{
		TransferID: "xfer_0000000000000002", AccountID: auditAccount, SessionID: "sess_000000000002", EndpointID: "audit-endpoint-2",
		Tier: "link", Direction: "download", Path: "/var/backups/db.sqlite", Status: "completed", Bytes: 52428800, TotalBytes: &total,
		SHA256: str("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), Truncated: &yes,
		ClientID: str("client-1"), MCPClientName: str("codex"),
		CreatedAt: "2026-01-01T00:00:02.000Z", UpdatedAt: "2026-01-01T00:00:09.000Z", FinishedAt: str("2026-01-01T00:00:09.000Z"),
	})
	log.Save(audit.FileTransferRow{
		TransferID: "xfer_0000000000000003", AccountID: auditAccount, SessionID: "sess_000000000003", EndpointID: "audit-endpoint-3",
		Tier: "link", Direction: "upload", Path: "/srv/backup.tgz", Status: "failed", Bytes: 1048576, TotalBytes: &total,
		Error:         str("connection lost after the commit was sent and before its reply arrived; the outcome is unknown — inspect the destination (size, sha256) before retrying"),
		CommitOutcome: str("unknown"), Cleanup: str("failed"), StagingPath: str("/srv/.backup.tgz.x7f1a2b3.tmp"),
		ClientID:  str("client-2"),
		CreatedAt: "2026-01-01T00:00:03.000Z", UpdatedAt: "2026-01-01T00:00:05.000Z", FinishedAt: str("2026-01-01T00:00:05.000Z"),
	})

	cfg := &config.Config{}
	cfg.Server.ExternalURL = externalURL
	cfg.Hydra.PublicURL = "http://localhost:4444"
	resolve := auth.Resolver(func(_ context.Context, tok string) *auth.Principal {
		if tok == "ui" {
			return &auth.Principal{AccountID: auditAccount, Scopes: []string{"ui"}}
		}
		return nil
	})
	ts := httptest.NewServer(New(Params{
		Config: cfg, Resolve: resolve, StaticFS: os.DirFS(t.TempDir()), BuildInfo: buildinfo.Info{},
		Audit: &rest.Audit{Sessions: audit.NewSessions(db), Signings: audit.NewSignings(db), FileTransfers: log},
	}))
	t.Cleanup(ts.Close)

	st, page := doJSON(t, ts, "GET", "/api/audit/file-transfers?limit=2", "")
	assertBodyGolden(t, "audit-file-transfers-page1", st, page)
	cursor, _ := page["nextCursor"].(string)
	if cursor == "" {
		t.Fatal("page 1 has no cursor")
	}
	st, page2 := doJSON(t, ts, "GET", "/api/audit/file-transfers?limit=2&cursor="+cursor, "")
	assertBodyGolden(t, "audit-file-transfers-page2", st, page2)

	// Filters narrow; an unknown value is a 400.
	_, bySession := doJSON(t, ts, "GET", "/api/audit/file-transfers?sessionId=sess_000000000003", "")
	if rows, _ := bySession["rows"].([]any); len(rows) != 1 {
		t.Errorf("sessionId filter: %+v", bySession)
	}
	_, byTier := doJSON(t, ts, "GET", "/api/audit/file-transfers?tier=link&direction=upload", "")
	if rows, _ := byTier["rows"].([]any); len(rows) != 1 {
		t.Errorf("tier+direction filter: %+v", byTier)
	}
	st, inv := doJSON(t, ts, "GET", "/api/audit/file-transfers?direction=sideways", "")
	assertBodyGolden(t, "audit-file-transfers-invalid-direction", st, inv)
}
