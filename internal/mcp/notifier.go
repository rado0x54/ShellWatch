// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Server -> client notifications for one MCP session (docs/api/mcp-tools.md
// "Notifications"): notifications/shellwatch/output_available, debounced per
// session, and notifications/shellwatch/session_status on every status
// change — only for sessions the agent owns.
package mcp

import (
	"sync"
	"time"

	"github.com/rado0x54/shellwatch/internal/terminal"
)

const (
	notificationOutputAvailable = "notifications/shellwatch/output_available"
	notificationSessionStatus   = "notifications/shellwatch/session_status"
	defaultNotifyDebounce       = 100 * time.Millisecond
)

// notifySource is the slice of terminal.Manager the notifier needs.
type notifySource interface {
	SubscribeOutput(fn func(sessionID string, offset int64)) func()
	SubscribeStatus(fn func(terminal.StatusEvent)) func()
	GetSession(sessionID string) *terminal.Session
}

// outputAvailableParams / sessionStatusParams are the documented payloads.
type outputAvailableParams struct {
	SessionID string `json:"sessionId"`
	Offset    int64  `json:"offset"`
}

type sessionStatusParams struct {
	SessionID  string `json:"sessionId"`
	Status     string `json:"status"`
	EndpointID string `json:"endpointId,omitempty"`
}

type notifier struct {
	src      notifySource
	owns     func(sessionID string) bool
	send     func(method string, params any)
	debounce time.Duration

	mu      sync.Mutex
	pending map[string]*pendingOutput
	closed  bool
	unsubs  []func()
}

type pendingOutput struct {
	timer  *time.Timer
	offset int64
}

// attachNotifier subscribes to the manager and forwards events for owned
// sessions through send. Call destroy when the MCP session ends.
func attachNotifier(src notifySource, owns func(string) bool, debounce time.Duration, send func(string, any)) *notifier {
	if debounce <= 0 {
		debounce = defaultNotifyDebounce
	}
	n := &notifier{src: src, owns: owns, send: send, debounce: debounce, pending: map[string]*pendingOutput{}}
	n.unsubs = append(n.unsubs, src.SubscribeOutput(n.onOutput), src.SubscribeStatus(n.onStatus))
	return n
}

// onOutput coalesces a burst of output into one notification per session
// carrying the newest buffer offset (notifications.ts onOutput).
func (n *notifier) onOutput(sessionID string, offset int64) {
	if !n.owns(sessionID) {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return
	}
	if p, ok := n.pending[sessionID]; ok {
		p.offset = offset
		p.timer.Reset(n.debounce)
		return
	}
	p := &pendingOutput{offset: offset}
	p.timer = time.AfterFunc(n.debounce, func() { n.fire(sessionID) })
	n.pending[sessionID] = p
}

func (n *notifier) fire(sessionID string) {
	n.mu.Lock()
	p, ok := n.pending[sessionID]
	if ok {
		delete(n.pending, sessionID)
	}
	closed := n.closed
	n.mu.Unlock()
	if !ok || closed {
		return
	}
	n.send(notificationOutputAvailable, outputAvailableParams{SessionID: sessionID, Offset: p.offset})
}

// onStatus forwards a status change immediately; endpointId is omitted when
// the session is already gone (notifications.ts onStatusChange).
func (n *notifier) onStatus(ev terminal.StatusEvent) {
	if !n.owns(ev.SessionID) {
		return
	}
	n.mu.Lock()
	closed := n.closed
	n.mu.Unlock()
	if closed {
		return
	}
	params := sessionStatusParams{SessionID: ev.SessionID, Status: string(ev.Status)}
	if sess := n.src.GetSession(ev.SessionID); sess != nil {
		params.EndpointID = sess.EndpointID
	}
	n.send(notificationSessionStatus, params)
}

// destroy unsubscribes and drops pending timers.
func (n *notifier) destroy() {
	n.mu.Lock()
	n.closed = true
	for id, p := range n.pending {
		p.timer.Stop()
		delete(n.pending, id)
	}
	unsubs := n.unsubs
	n.unsubs = nil
	n.mu.Unlock()
	for _, u := range unsubs {
		u()
	}
}
