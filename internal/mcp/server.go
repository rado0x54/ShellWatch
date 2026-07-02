// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package mcp is the MCP surface (port of src/mcp/): the 7 tools delegating
// to an AgentSession, over the official go-sdk streamable-HTTP transport. Each
// client connection gets its own Server + AgentSession (per-client isolation,
// spec §5.10). Tool responses are text content carrying JSON, matching the
// Node wire exactly (pinned by the mcp-* goldens).
package mcp

import (
	"context"
	"encoding/json"
	"net/http"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// Deps are the MCP surface's collaborators.
type Deps struct {
	AgentDeps agent.Deps
	Keys      *store.SSHKeys
	MaxOwned  int
}

// Handler returns the /mcp streamable-HTTP handler. Each new session gets a
// fresh Server bound to a fresh AgentSession scoped to the request's account.
func (d *Deps) Handler() http.Handler {
	return mcpsdk.NewStreamableHTTPHandler(func(r *http.Request) *mcpsdk.Server {
		principal, ok := auth.PrincipalFrom(r.Context())
		if !ok {
			return nil
		}
		as := agent.New(d.AgentDeps, principal.AccountID, clientIP(r), d.MaxOwned)
		return d.buildServer(as)
	}, nil)
}

func (d *Deps) buildServer(as *agent.Session) *mcpsdk.Server {
	srv := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "shellwatch", Version: "1.0.0"}, nil)
	registerSessionTools(srv, as)
	registerEndpointTools(srv, as)
	registerKeyTools(srv, as, d.Keys)
	return srv
}

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

func clientIP(r *http.Request) string {
	// Best-effort peer; the trust-proxy handling lands with the middleware.
	host := r.RemoteAddr
	if i := lastColon(host); i >= 0 {
		host = host[:i]
	}
	return host
}

func lastColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}

// isoMillis matches Node's Date.toISOString().
const isoMillis = "2006-01-02T15:04:05.000Z"

var _ = context.Background
var _ = terminal.SourceMCP
