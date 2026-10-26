// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Audit REST (port of src/server/routes/audit.ts): keyset-paginated session +
// signing logs, account-scoped, with source/outcome filter validation. Pinned
// by the audit-* goldens.
package rest

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/audit"
	"github.com/rado0x54/shellwatch/internal/notify"
)

// AdminCheck reports whether an account holds the admin role (satisfied by
// *store.Accounts).
type AdminCheck interface {
	IsAdmin(ctx context.Context, accountID string) bool
}

// Audit wires the audit read routes.
type Audit struct {
	Sessions *audit.Sessions
	Signings *audit.Signings
	// Notify serves the notification log (#252) — the third audit surface.
	Notify *notify.Service
	// OAuthClients serves the OAuth client registration log (#242) — the
	// fourth audit surface, and the only one that is NOT account-scoped: DCR
	// and CIMD both run before any account exists. Admin-only, hence IsAdmin.
	OAuthClients *audit.OAuthClients
	IsAdmin      AdminCheck
}

var (
	sourceValues  = map[string]bool{"endpoint-auth": true, "agent-forwarding": true, "agent-proxy": true, "endpoint-admin": true}
	outcomeValues = map[string]bool{"approved": true, "denied": true, "expired": true, "cancelled": true}
)

func (a *Audit) Mount(r chi.Router) {
	r.Get("/api/audit/sessions", a.listSessions)
	r.Get("/api/audit/signings", a.listSignings)
	r.Get("/api/audit/signings/{id}", a.getSigning)
	if a.Notify != nil {
		r.Get("/api/audit/notifications", a.listNotifications)
	}
	if a.OAuthClients != nil && a.IsAdmin != nil {
		r.Get("/api/audit/oauth-clients", a.listOAuthClients)
	}
}

var (
	oauthOriginValues = map[string]bool{audit.OriginDCR: true, audit.OriginCIMD: true}
	oauthEventValues  = map[string]bool{
		audit.EventRegistered: true, audit.EventRefreshed: true, audit.EventRejected: true,
	}
)

// listOAuthClients serves the registration log. Unlike every other audit
// route this one is NOT account-filtered — the rows are pre-account by nature
// — so the admin role is the only thing standing in front of it.
func (a *Audit) listOAuthClients(w http.ResponseWriter, r *http.Request) {
	if !a.IsAdmin.IsAdmin(r.Context(), accountID(r)) {
		writeErr(w, 403, "Admin role required")
		return
	}
	q := r.URL.Query()
	if v := q.Get("origin"); v != "" && !oauthOriginValues[v] {
		writeErr(w, 400, "invalid origin filter")
		return
	}
	if v := q.Get("event"); v != "" && !oauthEventValues[v] {
		writeErr(w, 400, "invalid event filter")
		return
	}
	page, err := a.OAuthClients.List(r.Context(), audit.OAuthClientFilter{
		ClientID: q.Get("clientId"), Origin: q.Get("origin"), Event: q.Get("event"),
		Cursor: q.Get("cursor"), Limit: parseLimit(q.Get("limit")),
	})
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	writeJSON(w, 200, page)
}

func (a *Audit) listNotifications(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, err := a.Notify.List(r.Context(), accountID(r), q.Get("cursor"), parseLimit(q.Get("limit")))
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	writeJSON(w, 200, page)
}

func (a *Audit) listSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, err := a.Sessions.List(r.Context(), accountID(r), audit.SessionFilters{
		EndpointID: q.Get("endpointId"), From: q.Get("from"), To: q.Get("to"),
	}, q.Get("cursor"), parseLimit(q.Get("limit")))
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	writeJSON(w, 200, page)
}

func (a *Audit) listSignings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if s := q.Get("source"); s != "" && !sourceValues[s] {
		writeErr(w, 400, "invalid source filter")
		return
	}
	if o := q.Get("outcome"); o != "" && !outcomeValues[o] {
		writeErr(w, 400, "invalid outcome filter")
		return
	}
	page, err := a.Signings.List(r.Context(), accountID(r), audit.SigningFilters{
		Source: q.Get("source"), Outcome: q.Get("outcome"), From: q.Get("from"), To: q.Get("to"),
	}, q.Get("cursor"), parseLimit(q.Get("limit")))
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	writeJSON(w, 200, page)
}

func (a *Audit) getSigning(w http.ResponseWriter, r *http.Request) {
	row, err := a.Signings.GetByID(r.Context(), accountID(r), chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	if row == nil {
		writeErr(w, 404, "not found")
		return
	}
	writeJSON(w, 200, row)
}

func parseLimit(raw string) int {
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return n
}
