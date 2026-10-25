// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Audit REST (port of src/server/routes/audit.ts): keyset-paginated session +
// signing logs, account-scoped, with source/outcome filter validation. Pinned
// by the audit-* goldens.
package rest

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/audit"
)

// Audit wires the audit read routes.
type Audit struct {
	Sessions *audit.Sessions
	Signings *audit.Signings
}

var (
	sourceValues  = map[string]bool{"endpoint-auth": true, "agent-forwarding": true, "agent-proxy": true}
	outcomeValues = map[string]bool{"approved": true, "denied": true, "expired": true, "cancelled": true}
)

func (a *Audit) Mount(r chi.Router) {
	r.Get("/api/audit/sessions", a.listSessions)
	r.Get("/api/audit/signings", a.listSignings)
	r.Get("/api/audit/signings/{id}", a.getSigning)
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
