// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Account login-session management (/api/auth/sessions) REST (port of
// auth-sessions.ts): list the caller's authorized OAuth clients (Hydra consent
// sessions, one row per client), revoke one, or revoke all (step-up gated).
package rest

import (
	"context"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/hydra"
	"github.com/rado0x54/shellwatch/internal/webauthn"
)

// consentAdmin is the slice of the Hydra admin these routes need.
type consentAdmin interface {
	ListConsentSessions(ctx context.Context, subject string) ([]hydra.ConsentSession, error)
	RevokeConsentSessions(ctx context.Context, subject, clientID string) error
	RevokeLoginSessions(ctx context.Context, subject string) error
}

// AuthSessions wires the authorized-clients routes.
type AuthSessions struct {
	Admin       consentAdmin
	SPAClientID string
	StepUp      *webauthn.StepUpStore
}

func (a *AuthSessions) Mount(r chi.Router) {
	r.Get("/api/auth/sessions", a.list)
	r.With(a.StepUp.RequireStepUp(webauthn.ActionRevokeSession)).
		Delete("/api/auth/sessions/{clientId}", a.revoke)
	r.With(a.StepUp.RequireStepUp(webauthn.ActionRevokeAllSessions)).
		Post("/api/auth/sessions/revoke-all", a.revokeAll)
}

type authSessionView struct {
	ClientID     string   `json:"clientId"`
	ClientName   string   `json:"clientName"`
	Scopes       []string `json:"scopes"`
	AuthorizedAt *string  `json:"authorizedAt"`
	CreatedAt    *string  `json:"createdAt"`
	Current      bool     `json:"current"`
}

func (a *AuthSessions) list(w http.ResponseWriter, r *http.Request) {
	acct := accountID(r)
	sessions, err := a.Admin.ListConsentSessions(r.Context(), acct)
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	// Collapse to one row per client_id, keeping the most recently handled grant.
	byClient := map[string]authSessionView{}
	for _, s := range sessions {
		if s.ConsentRequest == nil {
			continue
		}
		client := s.ConsentRequest.Client
		if client.ClientID == "" {
			continue
		}
		handledAt := nzp(s.HandledAt)
		if existing, ok := byClient[client.ClientID]; ok {
			if strOr(existing.AuthorizedAt) >= strOr(handledAt) {
				continue
			}
		}
		name := client.ClientName
		if name == "" {
			name = client.ClientID
		}
		scopes := s.GrantScope
		if scopes == nil {
			scopes = []string{}
		}
		byClient[client.ClientID] = authSessionView{
			ClientID: client.ClientID, ClientName: name, Scopes: scopes,
			AuthorizedAt: handledAt, CreatedAt: nzp(client.CreatedAt),
			Current: client.ClientID == a.SPAClientID,
		}
	}
	list := make([]authSessionView, 0, len(byClient))
	for _, v := range byClient {
		list = append(list, v)
	}
	// Web UI client first; the rest most-recently-authorized first.
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Current != list[j].Current {
			return list[i].Current
		}
		return strOr(list[j].AuthorizedAt) < strOr(list[i].AuthorizedAt)
	})
	writeJSON(w, 200, map[string]any{"sessions": list})
}

func (a *AuthSessions) revoke(w http.ResponseWriter, r *http.Request) {
	if err := a.Admin.RevokeConsentSessions(r.Context(), accountID(r), chi.URLParam(r, "clientId")); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "revoked"})
}

func (a *AuthSessions) revokeAll(w http.ResponseWriter, r *http.Request) {
	acct := accountID(r)
	if err := a.Admin.RevokeConsentSessions(r.Context(), acct, ""); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	if err := a.Admin.RevokeLoginSessions(r.Context(), acct); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "revoked_all"})
}

func nzp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func strOr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
