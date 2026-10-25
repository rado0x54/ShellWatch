// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Stateful streamable-HTTP handling for /mcp with ShellWatch's own session
// table. The go-sdk's StreamableHTTPHandler would do this for us, but it hides
// the per-session Connection and its ServerSession can only emit the
// spec-defined notifications — there is no public way to send the custom
// notifications/shellwatch/* methods the contract documents. Owning the table
// (same request rules as the sdk handler: Accept/Content-Type checks, 404 for
// unknown ids, idle timeout suspended while a request or SSE stream is live)
// lets each session keep its Connection and write those frames directly;
// everything else — JSON-RPC, SSE streams, resumability — is still the sdk's
// StreamableServerTransport.
package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/realip"
)

const sessionIDHeader = "Mcp-Session-Id"

// liveSession is one connected MCP client: its sdk session + transport, the
// account that opened it, its AgentSession and notifier, and the idle timer.
type liveSession struct {
	id        string
	accountID string
	as        *agent.Session
	ss        *mcpsdk.ServerSession
	transport *mcpsdk.StreamableServerTransport
	conn      mcpsdk.Connection
	notifier  *notifier

	// Idle timeout bookkeeping (mirrors the sdk handler): the timer only runs
	// while no request — including a held SSE GET — is in flight.
	timeout time.Duration
	timerMu sync.Mutex
	refs    int
	timer   *time.Timer
}

// notify writes a server -> client notification straight onto the session's
// transport connection. With no request in the context it lands on the
// client's standalone SSE stream (or its subscriptions/listen stream); a
// client that holds no such stream simply misses it, exactly like Node.
func (ls *liveSession) notify(method string, params any) {
	raw, err := json.Marshal(params)
	if err != nil {
		return
	}
	if err := ls.conn.Write(context.Background(), &jsonrpc.Request{Method: method, Params: raw}); err != nil {
		slog.Debug("mcp notification not delivered", "session", ls.id, "method", method, "err", err)
	}
}

func (ls *liveSession) hold() {
	if ls.timeout <= 0 {
		return
	}
	ls.timerMu.Lock()
	defer ls.timerMu.Unlock()
	if ls.timer == nil {
		return
	}
	if ls.refs == 0 {
		ls.timer.Stop()
	}
	ls.refs++
}

func (ls *liveSession) release() {
	if ls.timeout <= 0 {
		return
	}
	ls.timerMu.Lock()
	defer ls.timerMu.Unlock()
	if ls.timer == nil {
		return
	}
	ls.refs--
	if ls.refs == 0 {
		ls.timer.Reset(ls.timeout)
	}
}

func (ls *liveSession) stopTimer() {
	ls.timerMu.Lock()
	defer ls.timerMu.Unlock()
	if ls.timer != nil {
		ls.timer.Stop()
		ls.timer = nil
	}
}

// capturingTransport wraps the sdk transport so Server.Connect hands us the
// Connection it will use; it forwards the protocol-version capability.
type capturingTransport struct {
	inner *mcpsdk.StreamableServerTransport
	conn  mcpsdk.Connection
}

func (t *capturingTransport) Connect(ctx context.Context) (mcpsdk.Connection, error) {
	c, err := t.inner.Connect(ctx)
	t.conn = c
	return c, err
}

func (t *capturingTransport) SupportsProtocolVersion(v string) bool {
	return t.inner.SupportsProtocolVersion(v)
}

// Handler returns the /mcp handler. Each new session gets a fresh Server
// bound to a fresh AgentSession scoped to the request's account; every later
// request must carry the id AND come from the same account — a foreign
// account replaying another's Mcp-Session-Id gets the same 404 as an unknown
// or stale one, never a disclosure that the id exists (http-transport.ts:87-102).
func (d *Deps) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.PrincipalFrom(r.Context())
		if !ok {
			http.Error(w, "no server available", http.StatusBadRequest)
			return
		}
		if id := r.Header.Get(sessionIDHeader); id != "" {
			v, known := d.sessions.Load(id)
			if !known || v.(*liveSession).accountID != principal.AccountID {
				sendSessionNotFound(w)
				return
			}
			d.serveExisting(w, r, v.(*liveSession))
			return
		}
		switch r.Method {
		case http.MethodPost:
			d.serveNewSession(w, r, principal)
		case http.MethodGet:
			http.Error(w, "Bad Request: GET requires an Mcp-Session-Id header", http.StatusBadRequest)
		case http.MethodDelete:
			http.Error(w, "Bad Request: DELETE requires an Mcp-Session-Id header", http.StatusBadRequest)
		default:
			w.Header().Set("Allow", "GET, POST, DELETE")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})
}

func (d *Deps) serveExisting(w http.ResponseWriter, r *http.Request, ls *liveSession) {
	switch r.Method {
	case http.MethodGet:
		if _, streamOK := streamableAccepts(r.Header.Values("Accept")); !streamOK {
			http.Error(w, "Accept must contain 'text/event-stream' for GET requests", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		if !postHeadersOK(w, r) {
			return
		}
	case http.MethodDelete:
		_ = ls.ss.Close()
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	ls.hold()
	defer ls.release()
	ls.transport.ServeHTTP(w, r)
}

// serveNewSession handles the first POST of a client (its initialize call):
// builds the per-account Server + AgentSession, connects the sdk session over
// a transport we keep a handle on, registers the session, and serves the
// request. A first message that is not initialize leaves InitializeParams nil
// and the session is closed again on the way out.
func (d *Deps) serveNewSession(w http.ResponseWriter, r *http.Request, principal auth.Principal) {
	if !postHeadersOK(w, r) {
		return
	}
	maxOwned := -1 // unresolved -> agent.New defaults to 5; explicit 0 blocks
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
	srv := d.buildServer(as, instructions)

	id := d.newSessionID()
	transport := &mcpsdk.StreamableServerTransport{SessionID: id}
	wrapped := &capturingTransport{inner: transport}
	ss, err := srv.Connect(r.Context(), wrapped, nil)
	if err != nil {
		slog.Error("mcp: connect failed", "err", err)
		http.Error(w, "failed connection", http.StatusInternalServerError)
		return
	}
	ls := &liveSession{
		id: id, accountID: principal.AccountID, as: as, ss: ss,
		transport: transport, conn: wrapped.conn, timeout: d.SessionTimeout,
	}
	ls.notifier = attachNotifier(d.AgentDeps.Manager, as.Owns, d.NotifyDebounce, ls.notify)
	if ls.timeout > 0 {
		ls.timer = time.AfterFunc(ls.timeout, func() { _ = ss.Close() })
	}
	// Registered before the client learns the id, so the ownership check has
	// no window. When the session closes (client DELETE, idle expiry, init
	// failure, shutdown) the AgentSession is destroyed so its terminals close
	// with reason agent-disconnect (http-transport.ts:144).
	d.sessions.Store(id, ls)
	go func() {
		_ = ss.Wait()
		d.sessions.Delete(id)
		ls.stopTimer()
		ls.notifier.destroy()
		as.Destroy()
	}()
	defer func() {
		if ss.InitializeParams() == nil {
			_ = ss.Close()
		}
	}()
	ls.hold()
	defer ls.release()
	transport.ServeHTTP(w, r)
}

// postHeadersOK applies the sdk handler's POST preconditions.
func postHeadersOK(w http.ResponseWriter, r *http.Request) bool {
	if baseMediaType(r.Header.Get("Content-Type")) != "application/json" {
		http.Error(w, "Content-Type must be 'application/json'", http.StatusUnsupportedMediaType)
		return false
	}
	jsonOK, streamOK := streamableAccepts(r.Header.Values("Accept"))
	if !jsonOK || !streamOK {
		http.Error(w, "Accept must contain both 'application/json' and 'text/event-stream'", http.StatusBadRequest)
		return false
	}
	return true
}

// streamableAccepts reports whether the Accept header admits JSON and SSE
// (a wildcard admits both).
func streamableAccepts(values []string) (jsonOK, streamOK bool) {
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			mt := baseMediaType(part)
			switch {
			case mt == "*/*":
				jsonOK, streamOK = true, true
			case mt == "application/json" || mt == "application/*":
				jsonOK = true
			case mt == "text/event-stream" || mt == "text/*":
				streamOK = true
			}
		}
	}
	return jsonOK, streamOK
}

func baseMediaType(value string) string {
	mt, _, err := mime.ParseMediaType(strings.TrimSpace(value))
	if err != nil {
		return strings.ToLower(strings.TrimSpace(strings.SplitN(value, ";", 2)[0]))
	}
	return mt
}
