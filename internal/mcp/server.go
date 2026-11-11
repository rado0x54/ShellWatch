// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package mcp is the MCP surface: a stateless dual-era streamable-HTTP server
// (spec 2026-07-28 + the 2025-11-25/2025-06-18 handshake eras, #243) exposing
// the 7 shellwatch tools and the shellwatch://sessions resources. There are no
// protocol-level sessions: every request builds a fresh Server bound to an
// AgentSession scoped to the request's (account, OAuth client); terminal
// sessions are the durable handles. Server-initiated notifications are
// resources/updated events over subscriptions/listen; legacy clients long-poll
// shellwatch_read_output with waitMs. Tool responses are text content carrying
// JSON (pinned by the mcp-* goldens).
package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/realip"
	"github.com/rado0x54/shellwatch/internal/store"
)

// protocolVersions are the eras this server serves (docs/api/mcp-tools.md).
// 2025-03-26 and 2024-11-05 are deliberately excluded — ShellWatch never
// shipped against them.
var protocolVersions = []string{"2026-07-28", "2025-11-25", "2025-06-18"}

// Deps are the MCP surface's collaborators.
type Deps struct {
	AgentDeps agent.Deps
	Keys      *store.SSHKeys
	// MaxOwned resolves the account's concurrent-session cap (accounts.
	// max_sessions). nil/miss -> agent default (5).
	MaxOwned func(ctx context.Context, accountID string) (int, bool)
	// Version is the serverInfo version ("" falls back to "1.0.0").
	Version string
	// NotifyDebounce coalesces per-session resources/updated notifications for
	// output bursts (notifications.mcp.debounceMs; 0 -> 100ms).
	NotifyDebounce time.Duration
}

// Handler returns the /mcp handler: the sdk's stateless streamable-HTTP
// handler over a per-request Server. Stateless serves both eras — modern
// (>= 2026-07-28) requests carry their identity in _meta, legacy clients get a
// temporary default-initialized session per POST and no Mcp-Session-Id;
// GET/DELETE answer 405. Localhost DNS-rebinding protection is disabled:
// /mcp sits behind the bearer gate + IP allowlist, and production deployments
// commonly bind loopback behind a reverse proxy whose forwarded Host is not
// loopback.
func (d *Deps) Handler() http.Handler {
	return mcpsdk.NewStreamableHTTPHandler(func(r *http.Request) *mcpsdk.Server {
		principal, ok := auth.PrincipalFrom(r.Context())
		if !ok {
			return nil // sdk answers 400; the bearer gate makes this unreachable
		}
		return d.buildServer(r, principal)
	}, &mcpsdk.StreamableHTTPOptions{
		Stateless:                  true,
		DisableLocalhostProtection: true,
	})
}

// buildServer assembles the per-request sdk Server: tools and resources bound
// to an AgentSession for the request's (account, OAuth client), the live
// instructions, and the resource watcher feeding resources/updated.
func (d *Deps) buildServer(r *http.Request, principal auth.Principal) *mcpsdk.Server {
	maxOwned := -1 // unresolved -> agent default (5); explicit 0 blocks
	if d.MaxOwned != nil {
		if m, ok := d.MaxOwned(r.Context(), principal.AccountID); ok {
			maxOwned = m
		}
	}
	as := agent.New(agent.Params{
		Deps:      d.AgentDeps,
		AccountID: principal.AccountID,
		ClientID:  principal.ClientID,
		SourceIP:  realip.FromRequest(r),
		MaxOwned:  maxOwned,
	})
	// Agent attribution for the approval UI and audit log: default to the
	// OAuth client_id (always known, tamper-proof). A 2026-07-28 client's
	// per-request _meta clientInfo overrides it with the richer self-reported
	// name (captureClientInfo); a legacy client's initialize params never reach
	// stateless tool calls, so the client_id is all we have for it.
	as.SetClientInfo(principal.ClientID, "")

	// Instructions carry the account's live endpoint list; server/discover and
	// the legacy initialize answer both return them.
	instructions := ""
	if eps, err := as.ListEndpoints(r.Context()); err == nil {
		instructions = buildInstructions(eps)
	}

	version := d.Version
	if version == "" {
		version = "1.0.0"
	}

	var srv *mcpsdk.Server
	w := newWatcher(d.AgentDeps.Manager, as.Owns, d.NotifyDebounce, func(uri string) {
		// srv is assigned below, before any subscription can exist.
		_ = srv.ResourceUpdated(context.Background(), &mcpsdk.ResourceUpdatedNotificationParams{URI: uri})
	})
	srv = mcpsdk.NewServer(&mcpsdk.Implementation{Name: "shellwatch", Version: version}, &mcpsdk.ServerOptions{
		Instructions: instructions,
		// Logging is deprecated (SEP-2577) and ShellWatch never emitted it —
		// an empty struct suppresses the sdk's historical {"logging":{}}
		// default; tools/resources capabilities are still inferred.
		Capabilities:              &mcpsdk.ServerCapabilities{},
		SupportedProtocolVersions: protocolVersions,
		SetCacheable:              setCacheable,
		SubscribeHandler:          w.subscribe,
		// Teardown rides the subscribe call's request context (watcher), not
		// the unsubscribe method — see watcher.subscribe.
		UnsubscribeHandler: func(context.Context, *mcpsdk.UnsubscribeRequest) error { return nil },
	})
	registerSessionTools(srv, as)
	registerEndpointTools(srv, as)
	registerKeyTools(srv, as, d.Keys)
	registerSessionResources(srv, as, d.AgentDeps.Manager)
	return srv
}

// setCacheable stamps the SEP-2549 cache-control fields: everything is
// account-scoped ("private"); only the static tool set is worth caching.
func setCacheable(_ context.Context, req mcpsdk.Request, c *mcpsdk.Cacheable) {
	c.CacheScope = "private"
	if _, ok := req.(*mcpsdk.ListToolsRequest); ok {
		c.TTLMs = 3600000
	}
}

// captureClientInfo records the request's advertised client name/version on
// the AgentSession (approval UI + audit). Modern clients send it per request
// in _meta; for legacy clients the sdk falls back to initialize params, which
// a stateless temporary session does not carry — their identity is simply
// unavailable (documented in docs/api/mcp-tools.md).
func captureClientInfo(as *agent.Session, req *mcpsdk.CallToolRequest) {
	if ci := req.ClientInfo(); ci != nil {
		as.SetClientInfo(ci.Name, ci.Version)
	}
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

// isoMillis matches Node's Date.toISOString().
const isoMillis = clock.ISOMillis
