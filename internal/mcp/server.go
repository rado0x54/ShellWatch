// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package mcp is the MCP surface (port of src/mcp/): the 7 tools delegating
// to an AgentSession, over the official go-sdk streamable-HTTP transport. Each
// client connection gets its own Server + AgentSession (per-client isolation,
// spec §5.10). Tool responses are text content carrying JSON, matching the
// Node wire exactly (pinned by the mcp-* goldens).
package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/realip"
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

	// owners maps a live Mcp-Session-Id -> *ownedSession. Populated while the
	// session's first message (initialize) is handled — before the client
	// ever learns the id — and removed when the session closes. Backs the
	// cross-account hijack guard below (http-transport.ts #128) and
	// account-deletion teardown (DropAccount).
	owners sync.Map
}

// ownedSession tracks one live MCP session's owner + handles for teardown.
// Immutable after insertion into owners.
type ownedSession struct {
	accountID string
	as        *agent.Session
	ss        *mcpsdk.ServerSession
}

// DropAccount tears down every live MCP session owned by accountID (account
// deleted): closes the go-sdk session, which destroys the AgentSession via
// the Wait hook. Returns the number of sessions dropped
// (http-transport.ts:58-72).
func (d *Deps) DropAccount(accountID string) int {
	dropped := 0
	d.owners.Range(func(key, value any) bool {
		os := value.(*ownedSession)
		if os.accountID != accountID {
			return true
		}
		d.owners.Delete(key)
		_ = os.ss.Close() // Wait hook destroys the AgentSession
		dropped++
		return true
	})
	return dropped
}

// Handler returns the /mcp streamable-HTTP handler. Each new session gets a
// fresh Server bound to a fresh AgentSession scoped to the request's account.
//
// The wrapper enforces session ownership BEFORE the go-sdk handler sees the
// request: a foreign account replaying another account's Mcp-Session-Id gets
// the SAME 404 as an unknown/stale one — never a disclosure that the id
// exists (port of the onRequest hook in src/mcp/http-transport.ts:87-102).
func (d *Deps) Handler() http.Handler {
	inner := mcpsdk.NewStreamableHTTPHandler(func(r *http.Request) *mcpsdk.Server {
		principal, ok := auth.PrincipalFrom(r.Context())
		if !ok {
			return nil
		}
		maxOwned := 0 // agent.New defaults to 5
		if d.MaxOwned != nil {
			if m, ok := d.MaxOwned(r.Context(), principal.AccountID); ok {
				maxOwned = m
			}
		}
		as := agent.New(d.AgentDeps, principal.AccountID, realip.FromRequest(r), maxOwned)
		// Instructions carry the account's live endpoint list (server.ts:32-73).
		instructions := ""
		if eps, err := as.ListEndpoints(r.Context()); err == nil {
			instructions = buildInstructions(eps)
		}
		return d.buildServer(as, principal.AccountID, instructions)
	}, &mcpsdk.StreamableHTTPOptions{
		// go-sdk's DNS-rebinding protection 403s a loopback local address with
		// a non-loopback Host — which is exactly a reverse-proxy deployment
		// (proxy -> 127.0.0.1 with Host: shellwatch.example.com). Node has no
		// such check; /mcp is already gated by OAuth scope + the IP allowlist.
		DisableLocalhostProtection: true,
		SessionTimeout:             d.SessionTimeout,
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := r.Header.Get("Mcp-Session-Id"); id != "" {
			owner, known := d.owners.Load(id)
			principal, ok := auth.PrincipalFrom(r.Context())
			// Unknown/stale ids get the same envelope as foreign ones —
			// falling through would leak go-sdk's plain-text 404 instead of
			// Node's JSON-RPC body.
			if !known || !ok || owner.(*ownedSession).accountID != principal.AccountID {
				sendSessionNotFound(w)
				return
			}
		}
		inner.ServeHTTP(w, r)
	})
}

// sendSessionNotFound matches Node's uniform stale/foreign-session response.
func sendSessionNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32001,"message":"Session not found"},"id":null}`))
}

func (d *Deps) buildServer(as *agent.Session, accountID, instructions string) *mcpsdk.Server {
	version := d.Version
	if version == "" {
		version = "1.0.0"
	}
	srv := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "shellwatch", Version: version}, &mcpsdk.ServerOptions{
		Instructions: instructions,
		GetSessionID: d.newSessionID,
		// On initialized: capture the client's advertised name/version for the
		// approval UI (agent-session clientInfo, M4).
		InitializedHandler: func(_ context.Context, req *mcpsdk.InitializedRequest) {
			if params := req.Session.InitializeParams(); params != nil && params.ClientInfo != nil {
				as.SetClientInfo(params.ClientInfo.Name, params.ClientInfo.Version)
			}
		},
	})
	// Ownership registration + disconnect teardown, armed on the FIRST message
	// the session processes — the initialize request itself, still before the
	// client learns the id, so the hijack pre-check has no window. Registering
	// here (not in GetSessionID) means an entry exists only for sessions that
	// actually bound — a server.Connect failure can't strand one. When the
	// session closes (client DELETE, idle expiry, init failure, shutdown),
	// destroy the AgentSession so its owned terminals close with reason
	// agent-disconnect (http-transport.ts:144).
	var armOnce sync.Once
	srv.AddReceivingMiddleware(func(next mcpsdk.MethodHandler) mcpsdk.MethodHandler {
		return func(ctx context.Context, method string, req mcpsdk.Request) (mcpsdk.Result, error) {
			if ss, ok := req.GetSession().(*mcpsdk.ServerSession); ok {
				armOnce.Do(func() {
					d.owners.Store(ss.ID(), &ownedSession{accountID: accountID, as: as, ss: ss})
					go func() {
						_ = ss.Wait()
						d.owners.Delete(ss.ID())
						as.Destroy()
					}()
				})
			}
			return next(ctx, method, req)
		}
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
func newSessionUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
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
const isoMillis = "2006-01-02T15:04:05.000Z"
