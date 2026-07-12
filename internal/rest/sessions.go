// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Sessions REST (port of src/server/routes/sessions.ts). POST returns the
// bare TerminalSession (contract item B, preserved); tail/list/close scope by
// account and 404 to avoid disclosing other accounts' sessions. Pinned by
// err-404-session-endpoint / err-404-session-tail.
package rest

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/api"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/realip"
	"github.com/rado0x54/shellwatch/internal/store"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// Sessions wires the session routes.
type Sessions struct {
	Manager   *terminal.Manager
	Endpoints *store.Endpoints
	Demo      *demo.Service
	// MaxSessions resolves an account's concurrent-session cap.
	MaxSessions func(ctx context.Context, accountID string) (int, bool)
}

func (s *Sessions) Mount(r chi.Router) {
	r.Post("/api/sessions", s.create)
	r.Get("/api/sessions", s.list)
	r.Get("/api/sessions/{sessionId}/tail", s.tail)
	r.Delete("/api/sessions/{sessionId}", s.close)
}

// toSessionDTO builds the bare TerminalSession wire shape. Optional fields
// omit when empty (matching the conditional spread in terminal-manager.ts).
func toSessionDTO(s terminal.Session) api.TerminalSession {
	return api.TerminalSession{
		SessionId: s.SessionID, EndpointId: s.EndpointID, AccountId: s.AccountID,
		Status: api.TerminalStatus(s.Status), Source: api.TerminalSource(s.Source),
		CreatedAt:        s.CreatedAt.UTC().Format(isoMillis),
		LastActivityAt:   s.LastActivityAt.UTC().Format(isoMillis),
		CloseReason:      strPtrIf(string(s.CloseReason)),
		SourceIp:         strPtrIf(s.SourceIP),
		McpReason:        strPtrIf(s.MCPReason),
		McpClientName:    strPtrIf(s.MCPClientName),
		McpClientVersion: strPtrIf(s.MCPClientVer),
	}
}

func (s *Sessions) create(w http.ResponseWriter, r *http.Request) {
	acc := accountID(r)
	if s.MaxSessions != nil {
		if max, ok := s.MaxSessions(r.Context(), acc); ok {
			open := 0
			for _, sess := range s.Manager.ListForAccount(acc) {
				if sess.Status == terminal.StatusOpen {
					open++
				}
			}
			if open >= max {
				writeErr(w, 429, "Maximum concurrent sessions ("+strconv.Itoa(max)+") reached")
				return
			}
		}
	}

	body := readRawBody(r)
	endpointID := stringField(body, "endpointId")

	ref, ok := s.resolveEndpoint(r.Context(), endpointID, acc)
	if !ok {
		writeErr(w, 404, "Endpoint not found")
		return
	}
	sess, err := s.Manager.Create(r.Context(), ref, acc, terminal.Trigger{
		Kind: terminal.SourceUI, SourceIP: realip.FromRequest(r),
	})
	if err != nil {
		// The SSH connect (incl. passkey signing handshake) failed — log the
		// reason server-side; the 400 body alone is easy to miss in the browser.
		slog.Warn("session create failed",
			"endpointId", ref.ID, "endpointLabel", ref.Label, "address",
			ref.Username+"@"+ref.Host, "err", err)
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, toSessionDTO(*sess))
}

func (s *Sessions) resolveEndpoint(ctx context.Context, id, accountID string) (terminal.EndpointRef, bool) {
	if demo.IsID(id) && s.Demo != nil {
		for _, e := range s.Demo.List(accountID) {
			if e.ID == id {
				return toRef(e), true
			}
		}
		return terminal.EndpointRef{}, false
	}
	ep, err := s.Endpoints.GetForAccount(ctx, id, accountID)
	if err != nil || ep == nil {
		return terminal.EndpointRef{}, false
	}
	return toRef(*ep), true
}

func toRef(e store.Endpoint) terminal.EndpointRef {
	return terminal.EndpointRef{
		ID: e.ID, Label: e.Label, AccountID: e.AccountID, Host: e.Host, Port: int(e.Port),
		Username: e.Username, UserVerification: e.UserVerification, AgentForward: e.AgentForward,
	}
}

func (s *Sessions) list(w http.ResponseWriter, r *http.Request) {
	sessions := s.Manager.ListForAccount(accountID(r))
	out := make([]api.TerminalSession, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, toSessionDTO(sess))
	}
	writeJSON(w, 200, map[string]any{"sessions": out})
}

func (s *Sessions) tail(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionId")
	sess := s.Manager.GetSession(sessionID)
	if sess == nil || sess.AccountID != accountID(r) {
		writeErr(w, 404, "Session not found")
		return
	}
	limit := 2000
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
			if limit > 8000 {
				limit = 8000
			}
		}
	}
	data := s.Manager.ReadOutputTail(sessionID, limit)
	writeJSON(w, 200, map[string]any{"data": string(data)})
}

func (s *Sessions) close(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionId")
	sess := s.Manager.GetSession(sessionID)
	if sess == nil || sess.AccountID != accountID(r) {
		writeErr(w, 404, "Session not found")
		return
	}
	s.Manager.Close(sessionID, terminal.CloseClientUI)
	writeJSON(w, 200, map[string]any{"status": "closed"})
}

func strPtrIf(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
