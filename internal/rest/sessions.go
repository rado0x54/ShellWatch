// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Sessions REST (port of src/server/routes/sessions.ts). POST returns the
// bare TerminalSession (contract item B, preserved); tail/list/close scope by
// account and 404 to avoid disclosing other accounts' sessions. Pinned by
// err-404-session-endpoint / err-404-session-tail.
package rest

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/api"
	"github.com/rado0x54/shellwatch/internal/apierr"
	"github.com/rado0x54/shellwatch/internal/endpointsvc"
	"github.com/rado0x54/shellwatch/internal/realip"
	"github.com/rado0x54/shellwatch/internal/sshx"
	"github.com/rado0x54/shellwatch/internal/terminal"
)

// Sessions wires the session routes.
type Sessions struct {
	Manager *terminal.Manager
	// Svc opens sessions (endpoint lookup + max_sessions).
	Svc *endpointsvc.Service
	// GuestAttached reports whether a ticket guest is attached to a session
	// (#306; ok=false for any other session). nil-able.
	GuestAttached func(sessionID string) (attached, ok bool)
}

func (s *Sessions) Mount(r chi.Router) {
	r.Post("/api/sessions", s.create)
	r.Get("/api/sessions", s.list)
	r.Get("/api/sessions/{sessionId}/tail", s.tail)
	r.Delete("/api/sessions/{sessionId}", s.close)
}

// toSessionDTO builds the bare TerminalSession wire shape. Optional fields
// omit when empty (matching the conditional spread in terminal-manager.ts).
// Guest sessions (source ticket) add the ticket fields and guestAttached.
func (h *Sessions) toSessionDTO(s terminal.Session) api.TerminalSession {
	dto := toSessionDTO(s)
	if s.Source == terminal.SourceTicket {
		label := s.TicketLabel
		dto.TicketId, dto.TicketLabel = strPtrIf(s.TicketID), &label
		if h.GuestAttached != nil {
			if attached, ok := h.GuestAttached(s.SessionID); ok {
				dto.GuestAttached = &attached
			}
		}
	}
	return dto
}

func toSessionDTO(s terminal.Session) api.TerminalSession {
	return api.TerminalSession{
		SessionId: s.SessionID, EndpointId: s.EndpointID, AccountId: s.AccountID,
		Status: api.TerminalStatus(s.Status), Source: api.TerminalSource(s.Source),
		CreatedAt:        s.CreatedAt.UTC().Format(isoMillis),
		LastActivityAt:   s.LastActivityAt.UTC().Format(isoMillis),
		CloseReason:      strPtrIf(string(s.CloseReason)),
		SourceIp:         strPtrIf(s.SourceIP),
		OwnerClientId:    strPtrIf(s.OwnerClientID),
		Reason:           strPtrIf(s.Reason),
		McpClientName:    strPtrIf(s.MCPClientName),
		McpClientVersion: strPtrIf(s.MCPClientVer),
	}
}

func (s *Sessions) create(w http.ResponseWriter, r *http.Request) {
	sess, err := s.Svc.Open(r.Context(), accountID(r), stringField(readRawBody(r), "endpointId"), terminal.Trigger{
		Kind: terminal.SourceUI, SourceIP: realip.FromRequest(r),
	})
	var limit *terminal.LimitError
	var notified *sshx.NotifiedError
	switch {
	case errors.Is(err, endpointsvc.ErrEndpointNotFound), errors.Is(err, endpointsvc.ErrEndpointLookup):
		writeErr(w, 404, "Endpoint not found")
	case errors.As(err, &limit):
		writeErr(w, 429, err.Error())
	case errors.As(err, &notified):
		// The connect failed and was published to the notification log (e.g.
		// a host-key mismatch, #252): the client dedupes its error toast
		// against the pushed notification by id. The Manager logs the reason.
		apierr.WriteNotified(w, 400, err.Error(), notified.NotificationID)
	case err != nil:
		writeErr(w, 400, err.Error())
	default:
		writeJSON(w, 200, toSessionDTO(*sess))
	}
}

func (s *Sessions) list(w http.ResponseWriter, r *http.Request) {
	sessions := s.Manager.ListForAccount(accountID(r))
	out := make([]api.TerminalSession, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, s.toSessionDTO(sess))
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
