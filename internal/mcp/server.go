// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package mcp is the MCP surface: the 7 tools delegating to an AgentSession
// over the official go-sdk streamable-HTTP transport, plus the
// notifications/shellwatch/* server notifications. Each client connection
// gets its own Server + AgentSession (per-client isolation, spec §5.10); the
// session table is ours (handler.go). Tool responses are text content
// carrying JSON (pinned by the mcp-* goldens).
package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/ids"
	"github.com/rado0x54/shellwatch/internal/store"
)

// Deps are the MCP surface's collaborators.
type Deps struct {
	AgentDeps agent.Deps
	Keys      *store.SSHKeys
	// MaxOwned resolves the account's concurrent-session cap (accounts.
	// max_sessions, http-transport.ts:113-124). nil/miss -> agent default (5).
	MaxOwned func(ctx context.Context, accountID string) (int, bool)
	// NewID mints Mcp-Session-Ids (Node uses randomUUID); nil falls back to a
	// local v4 generator.
	NewID func() string
	// Version is the serverInfo version (Node uses buildInfo.display; "" falls
	// back to "1.0.0").
	Version string
	// SessionTimeout closes MCP sessions with no in-flight HTTP activity for
	// this long (0 = never, the Node behavior). Wired from
	// mcp.sessionTimeoutMinutes; the sdk timer is suspended while any request
	// (including a held SSE GET stream) is active, so only clients that
	// actually vanished expire. Expiry runs the full Wait teardown below —
	// the AgentSession and all its SSH sessions close too.
	SessionTimeout time.Duration
	// NotifyDebounce coalesces output_available notifications per session
	// (notifications.mcp.debounceMs; 0 -> 100ms).
	NotifyDebounce time.Duration

	// sessions maps a live Mcp-Session-Id -> *liveSession (handler.go).
	// Populated before the client learns the id and removed when the session
	// closes; backs the cross-account guard and DropAccount.
	sessions sync.Map
}

// DropAccount tears down every live MCP session owned by accountID (account
// deleted): closes the go-sdk session, which destroys the AgentSession via
// the Wait hook. Returns the number of sessions dropped
// (http-transport.ts:58-72).
func (d *Deps) DropAccount(accountID string) int {
	dropped := 0
	d.sessions.Range(func(key, value any) bool {
		ls := value.(*liveSession)
		if ls.accountID != accountID {
			return true
		}
		d.sessions.Delete(key)
		_ = ls.ss.Close() // Wait hook destroys the AgentSession
		dropped++
		return true
	})
	return dropped
}

// sendSessionNotFound matches Node's uniform stale/foreign-session response.
func sendSessionNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32001,"message":"Session not found"},"id":null}`))
}

// buildServer assembles the per-session sdk Server: tools bound to the
// AgentSession, the live instructions, and the clientInfo capture.
func (d *Deps) buildServer(as *agent.Session, instructions string) *mcpsdk.Server {
	version := d.Version
	if version == "" {
		version = "1.0.0"
	}
	srv := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "shellwatch", Version: version}, &mcpsdk.ServerOptions{
		Instructions: instructions,
		// On initialized: capture the client's advertised name/version for the
		// approval UI (agent-session clientInfo, M4).
		InitializedHandler: func(_ context.Context, req *mcpsdk.InitializedRequest) {
			if params := req.Session.InitializeParams(); params != nil && params.ClientInfo != nil {
				as.SetClientInfo(params.ClientInfo.Name, params.ClientInfo.Version)
			}
		},
	})
	registerSessionTools(srv, as)
	registerEndpointTools(srv, as)
	registerKeyTools(srv, as, d.Keys)
	return srv
}

func (d *Deps) newSessionID() string {
	if d.NewID != nil {
		return d.NewID()
	}
	return newSessionUUID()
}

// newSessionUUID mints a v4 UUID (Node uses randomUUID() for MCP session ids).
// Fallback only — production injects Deps.NewID (the composition root's
// generator), matching the rest of the codebase's NewID pattern.
func newSessionUUID() string { return ids.NewUUID() }

// --- helpers for the Node-compatible text-JSON result shape ---

// jsonResult returns a success CallToolResult whose single text block is the
// JSON of v (the @simplewebauthn-era Node shape: content[0].text = JSON).
func jsonResult(v any) (*mcpsdk.CallToolResult, error) {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errResult(err.Error()), nil
	}
	return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: string(raw)}}}, nil
}

// jsonResultCompact is like jsonResult without indentation (send_keys/close use
// compact JSON in Node).
func jsonResultCompact(v any) (*mcpsdk.CallToolResult, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return errResult(err.Error()), nil
	}
	return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: string(raw)}}}, nil
}

// errResult returns an isError result whose text block is a plain message.
func errResult(msg string) *mcpsdk.CallToolResult {
	return &mcpsdk.CallToolResult{IsError: true, Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: msg}}}
}

func decodeArgs(req *mcpsdk.CallToolRequest, v any) error {
	if len(req.Params.Arguments) == 0 {
		return nil
	}
	return json.Unmarshal(req.Params.Arguments, v)
}

// isoMillis matches Node's Date.toISOString().
const isoMillis = clock.ISOMillis
