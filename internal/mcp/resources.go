// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Terminal sessions as MCP resources (#243, docs/api/mcp-tools.md
// "Resources"): shellwatch://sessions (the owned-session list) and
// shellwatch://sessions/{sessionId} (one session document). A 2026-07-28
// client subscribes to them on subscriptions/listen (resourceSubscriptions)
// and receives notifications/resources/updated on new output (debounced per
// session) and on every status change — the spec-native replacement for the
// removed notifications/shellwatch/* methods.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rado0x54/shellwatch/internal/agent"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

const (
	sessionsResourceURI     = "shellwatch://sessions"
	sessionResourcePrefix   = "shellwatch://sessions/"
	sessionResourceTemplate = "shellwatch://sessions/{sessionId}"
	defaultNotifyDebounce   = 100 * time.Millisecond
	// protocolVersion20260728 gates resource subscriptions: on the stateless
	// transport only a subscriptions/listen stream can carry resources/updated,
	// and only its request context gives the watcher a teardown signal.
	protocolVersion20260728 = "2026-07-28"
)

// sessionDoc is the session resource's JSON shape (and the element shape of
// the list resource).
type sessionDoc struct {
	SessionID  string `json:"sessionId"`
	EndpointID string `json:"endpointId"`
	Status     string `json:"status"`
	CreatedAt  string `json:"createdAt"`
	Offset     int64  `json:"offset"`
}

func toSessionDoc(s terminal.Session, mgr *terminal.Manager) sessionDoc {
	offset, _ := mgr.OutputOffset(s.SessionID)
	return sessionDoc{
		SessionID:  s.SessionID,
		EndpointID: s.EndpointID,
		Status:     string(s.Status),
		CreatedAt:  s.CreatedAt.UTC().Format(isoMillis),
		Offset:     offset,
	}
}

// registerSessionResources adds the sessions list resource and the per-session
// resource template, both scoped to the AgentSession's (account, client).
func registerSessionResources(srv *mcpsdk.Server, as *agent.Session, mgr *terminal.Manager) {
	srv.AddResource(&mcpsdk.Resource{
		URI:         sessionsResourceURI,
		Name:        "sessions",
		Title:       "Your terminal sessions",
		Description: "The terminal sessions owned by your OAuth client. Updated on every session status change.",
		MIMEType:    "application/json",
	}, func(_ context.Context, _ *mcpsdk.ReadResourceRequest) (*mcpsdk.ReadResourceResult, error) {
		list := as.ListSessions()
		docs := make([]sessionDoc, 0, len(list))
		for _, s := range list {
			docs = append(docs, toSessionDoc(s, mgr))
		}
		return resourceJSON(sessionsResourceURI, map[string]any{"sessions": docs})
	})

	srv.AddResourceTemplate(&mcpsdk.ResourceTemplate{
		URITemplate: sessionResourceTemplate,
		Name:        "session",
		Title:       "One terminal session",
		Description: "A session's status and current output offset. Updated on status changes and (debounced) on new output; read new output with shellwatch_read_output.",
		MIMEType:    "application/json",
	}, func(_ context.Context, req *mcpsdk.ReadResourceRequest) (*mcpsdk.ReadResourceResult, error) {
		uri := req.Params.URI
		id, ok := strings.CutPrefix(uri, sessionResourcePrefix)
		if !ok || !as.Owns(id) {
			// Foreign and unknown ids are indistinguishable (no disclosure).
			return nil, mcpsdk.ResourceNotFoundError(uri)
		}
		sess := mgr.GetSession(id)
		if sess == nil {
			return nil, mcpsdk.ResourceNotFoundError(uri)
		}
		return resourceJSON(uri, toSessionDoc(*sess, mgr))
	})
}

func resourceJSON(uri string, v any) (*mcpsdk.ReadResourceResult, error) {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return &mcpsdk.ReadResourceResult{
		Contents: []*mcpsdk.ResourceContents{{URI: uri, MIMEType: "application/json", Text: string(raw)}},
	}, nil
}

// notifySource is the slice of terminal.Manager the watcher needs.
type notifySource interface {
	SubscribeOutput(fn func(sessionID string, offset int64)) func()
	SubscribeStatus(fn func(terminal.StatusEvent)) func()
}

// watcher turns manager fan-out into resources/updated notifications for the
// URIs this request's client subscribed to. It attaches to the manager only
// while subscriptions exist. Every registration is torn down when the
// subscribe call's request context ends — for subscriptions/listen that is the
// life of the stream — so a subscription from any other request (which could
// never receive the notifications anyway) cannot leak a manager subscription.
type watcher struct {
	src      notifySource
	owns     func(sessionID string) bool
	update   func(uri string)
	debounce time.Duration

	mu         sync.Mutex
	subscribed map[string]int           // uri -> registration refcount
	pending    map[string]*time.Timer   // session uri -> debounce timer
	unsubs     []func()
}

func newWatcher(src notifySource, owns func(string) bool, debounce time.Duration, update func(uri string)) *watcher {
	if debounce <= 0 {
		debounce = defaultNotifyDebounce
	}
	return &watcher{
		src: src, owns: owns, update: update, debounce: debounce,
		subscribed: map[string]int{}, pending: map[string]*time.Timer{},
	}
}

// subscribe is the sdk SubscribeHandler: validate the URI against this
// client's ownership, then register it for the life of the request context.
func (w *watcher) subscribe(ctx context.Context, req *mcpsdk.SubscribeRequest) error {
	if p := req.Session.InitializeParams(); p == nil || p.ProtocolVersion < protocolVersion20260728 {
		return fmt.Errorf("resource subscriptions require protocol version >= %s via subscriptions/listen; poll shellwatch_read_output with waitMs instead", protocolVersion20260728)
	}
	uri := req.Params.URI
	if uri != sessionsResourceURI {
		id, ok := strings.CutPrefix(uri, sessionResourcePrefix)
		if !ok || !w.owns(id) {
			return mcpsdk.ResourceNotFoundError(uri)
		}
	}
	w.acquire(uri)
	context.AfterFunc(ctx, func() { w.release(uri) })
	return nil
}

func (w *watcher) acquire(uri string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.subscribed) == 0 {
		w.unsubs = append(w.unsubs,
			w.src.SubscribeOutput(w.onOutput),
			w.src.SubscribeStatus(w.onStatus))
	}
	w.subscribed[uri]++
}

func (w *watcher) release(uri string) {
	w.mu.Lock()
	if w.subscribed[uri] > 0 {
		w.subscribed[uri]--
		if w.subscribed[uri] == 0 {
			delete(w.subscribed, uri)
			if t := w.pending[uri]; t != nil {
				t.Stop()
				delete(w.pending, uri)
			}
		}
	}
	var unsubs []func()
	if len(w.subscribed) == 0 {
		unsubs = w.unsubs
		w.unsubs = nil
		for id, t := range w.pending {
			t.Stop()
			delete(w.pending, id)
		}
	}
	w.mu.Unlock()
	for _, u := range unsubs {
		u()
	}
}

// onOutput coalesces a burst of output into one resources/updated per session
// URI carrying no payload — the client re-reads or calls read_output.
func (w *watcher) onOutput(sessionID string, _ int64) {
	uri := sessionResourcePrefix + sessionID
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.subscribed[uri] == 0 || !w.owns(sessionID) {
		return
	}
	if _, ok := w.pending[uri]; ok {
		return // a notification is already scheduled; it covers this burst
	}
	w.pending[uri] = time.AfterFunc(w.debounce, func() { w.fire(uri) })
}

func (w *watcher) fire(uri string) {
	w.mu.Lock()
	_, ok := w.pending[uri]
	delete(w.pending, uri)
	stillSubscribed := w.subscribed[uri] > 0
	w.mu.Unlock()
	if ok && stillSubscribed {
		w.update(uri)
	}
}

// onStatus forwards a status change immediately: to the session URI's
// subscribers and to the list resource's.
func (w *watcher) onStatus(ev terminal.StatusEvent) {
	if !w.owns(ev.SessionID) {
		return
	}
	uri := sessionResourcePrefix + ev.SessionID
	w.mu.Lock()
	sessionSubscribed := w.subscribed[uri] > 0
	listSubscribed := w.subscribed[sessionsResourceURI] > 0
	w.mu.Unlock()
	if sessionSubscribed {
		w.update(uri)
	}
	if listSubscribed {
		w.update(sessionsResourceURI)
	}
}
