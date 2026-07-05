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

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/realip"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// Deps are the MCP surface's collaborators.
type Deps struct {
	AgentDeps agent.Deps
	Keys      *store.SSHKeys
	MaxOwned  int

	// owners maps a live Mcp-Session-Id -> *ownedSession. Populated when a
	// session id is minted (GetSessionID), removed when the session closes.
	// Backs the cross-account hijack guard below (http-transport.ts #128) and
	// account-deletion teardown (DropAccount).
	owners sync.Map
}

// ownedSession tracks one live MCP session's owner + handles for teardown.
type ownedSession struct {
	accountID string
	as        *agent.Session

	mu sync.Mutex
	ss *mcpsdk.ServerSession // set once initialized; nil before
}

// DropAccount tears down every live MCP session owned by accountID (account
// deleted): closes the go-sdk session (which destroys the AgentSession via the
// Wait hook) or, for never-initialized sessions, destroys the AgentSession
// directly. Returns the number of sessions dropped (http-transport.ts:58-72).
func (d *Deps) DropAccount(accountID string) int {
	dropped := 0
	d.owners.Range(func(key, value any) bool {
		os := value.(*ownedSession)
		if os.accountID != accountID {
			return true
		}
		d.owners.Delete(key)
		os.mu.Lock()
		ss := os.ss
		os.mu.Unlock()
		if ss != nil {
			_ = ss.Close() // Wait hook destroys the AgentSession
		} else {
			os.as.Destroy()
		}
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
// the same 404 as a missing session — never a disclosure that the id exists
// (port of the onRequest hook in src/mcp/http-transport.ts:87-102).
func (d *Deps) Handler() http.Handler {
	inner := mcpsdk.NewStreamableHTTPHandler(func(r *http.Request) *mcpsdk.Server {
		principal, ok := auth.PrincipalFrom(r.Context())
		if !ok {
			return nil
		}
		as := agent.New(d.AgentDeps, principal.AccountID, clientIP(r), d.MaxOwned)
		return d.buildServer(as, principal.AccountID)
	}, &mcpsdk.StreamableHTTPOptions{
		// go-sdk's DNS-rebinding protection 403s a loopback local address with
		// a non-loopback Host — which is exactly a reverse-proxy deployment
		// (proxy -> 127.0.0.1 with Host: shellwatch.example.com). Node has no
		// such check; /mcp is already gated by OAuth scope + the IP allowlist.
		DisableLocalhostProtection: true,
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := r.Header.Get("Mcp-Session-Id"); id != "" {
			owner, known := d.owners.Load(id)
			principal, ok := auth.PrincipalFrom(r.Context())
			if known && (!ok || owner.(*ownedSession).accountID != principal.AccountID) {
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

func (d *Deps) buildServer(as *agent.Session, accountID string) *mcpsdk.Server {
	srv := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "shellwatch", Version: "1.0.0"}, &mcpsdk.ServerOptions{
		// Mint the session id ourselves so ownership is registered before the
		// id ever reaches a client (no initialize/first-use race).
		GetSessionID: func() string {
			id := newSessionUUID()
			d.owners.Store(id, &ownedSession{accountID: accountID, as: as})
			return id
		},
		// On initialized: capture the client's advertised name/version for the
		// approval UI, and arm the disconnect teardown — when this MCP session
		// closes (client DELETE, server shutdown), destroy the AgentSession so
		// its owned terminal sessions close with reason agent-disconnect
		// (http-transport.ts:144, agent-session.ts:167-176).
		InitializedHandler: func(_ context.Context, req *mcpsdk.InitializedRequest) {
			ss := req.Session
			if params := ss.InitializeParams(); params != nil && params.ClientInfo != nil {
				as.SetClientInfo(params.ClientInfo.Name, params.ClientInfo.Version)
			}
			if v, ok := d.owners.Load(ss.ID()); ok {
				os := v.(*ownedSession)
				os.mu.Lock()
				os.ss = ss
				os.mu.Unlock()
			}
			go func() {
				_ = ss.Wait()
				d.owners.Delete(ss.ID())
				as.Destroy()
			}()
		},
	})
	registerSessionTools(srv, as)
	registerEndpointTools(srv, as)
	registerKeyTools(srv, as, d.Keys)
	return srv
}

// newSessionUUID mints a v4 UUID (Node uses randomUUID() for MCP session ids).
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

func clientIP(r *http.Request) string {
	return realip.FromRequest(r)
}

// isoMillis matches Node's Date.toISOString().
const isoMillis = "2006-01-02T15:04:05.000Z"

var _ = context.Background
var _ = terminal.SourceMCP
