// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package mcp is the MCP surface: a stateless dual-era streamable-HTTP server
// (spec 2026-07-28 + the 2025-11-25/2025-06-18 handshake eras, #243) exposing
// the shellwatch tools (sessions, endpoints, keys, and the #263 file tools)
// and the shellwatch://sessions resources. There are no
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
	"log/slog"
	"net/http"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/clock"
	"github.com/rado0x54/shellwatch/internal/realip"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/transfer"
)

// protocolVersions are the eras this server serves (docs/api/mcp-tools.md).
// 2025-03-26 and 2024-11-05 are deliberately excluded — ShellWatch never
// shipped against them.
var protocolVersions = []string{"2026-07-28", "2025-11-25", "2025-06-18"}

// Deps are the MCP surface's collaborators.
type Deps struct {
	AgentDeps agent.Deps
	Keys      *store.SSHKeys
	// Version is the serverInfo version ("" falls back to "1.0.0").
	Version string
	// NotifyDebounce coalesces per-session resources/updated notifications for
	// output bursts (notifications.mcp.debounceMs; 0 -> 100ms).
	NotifyDebounce time.Duration
	// Transfers backs the file tools (#263); nil leaves them unregistered.
	Transfers *transfer.Service
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
	as := agent.New(agent.Params{
		Deps:      d.AgentDeps,
		AccountID: principal.AccountID,
		ClientID:  principal.ClientID,
		SourceIP:  realip.FromRequest(r),
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
	srv.AddReceivingMiddleware(logToolCalls(principal))
	registerSessionTools(srv, as)
	registerEndpointTools(srv, as)
	registerKeyTools(srv, as, d.Keys)
	if d.Transfers != nil {
		registerFileTools(srv, as, d.Transfers)
	}
	registerSessionResources(srv, as, d.AgentDeps.Manager)
	return srv
}

// setCacheable stamps the SEP-2549 cache-control fields: everything is
// account-scoped ("private"); only the static tool set is worth caching.
// toolSendKeys carries terminal input; its error text is not logged.
const toolSendKeys = "shellwatch_send_keys"

// logToolCalls logs one line per tools/call: tool, caller, duration, and the
// error text of a failed call. Arguments are deliberately not logged (they
// carry shell input and file contents).
func logToolCalls(principal auth.Principal) mcpsdk.Middleware {
	return func(next mcpsdk.MethodHandler) mcpsdk.MethodHandler {
		return func(ctx context.Context, method string, req mcpsdk.Request) (mcpsdk.Result, error) {
			call, ok := req.(*mcpsdk.CallToolRequest)
			if method != "tools/call" || !ok {
				return next(ctx, method, req)
			}
			start := time.Now()
			res, err := next(ctx, method, req)
			attrs := []any{"tool", call.Params.Name, "account", principal.AccountID, "client", principal.ClientID}
			if ci := call.ClientInfo(); ci != nil && ci.Name != "" {
				attrs = append(attrs, "mcpClient", ci.Name)
			}
			attrs = append(attrs, "dur", time.Since(start).Round(time.Millisecond))
			switch {
			case err != nil:
				slog.Warn("mcp: tool call failed", append(attrs, "err", err)...)
			case isToolError(res) && call.Params.Name == toolSendKeys:
				// Its errors echo the offending input ("unknown key: …").
				slog.Info("mcp: tool call returned an error", attrs...)
			case isToolError(res):
				slog.Info("mcp: tool call returned an error", append(attrs, "err", toolErrorText(res))...)
			default:
				slog.Info("mcp: tool call", attrs...)
			}
			return res, err
		}
	}
}

func isToolError(res mcpsdk.Result) bool {
	r, ok := res.(*mcpsdk.CallToolResult)
	return ok && r.IsError
}

// toolErrorText is the first text block of an error result, capped so a
// verbose tool error cannot flood the log.
func toolErrorText(res mcpsdk.Result) string {
	r, _ := res.(*mcpsdk.CallToolResult)
	for _, c := range r.Content {
		if t, ok := c.(*mcpsdk.TextContent); ok {
			if len(t.Text) > 300 {
				return t.Text[:300] + "…"
			}
			return t.Text
		}
	}
	return ""
}

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
