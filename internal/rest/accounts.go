// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Account self-service (/api/auth/me) + admin account management (/api/accounts)
// REST (port of accounts.ts). Pinned by account-* goldens.
package rest

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/config"
	"github.com/rado0x54/shellwatch/internal/demo"
	"github.com/rado0x54/shellwatch/internal/store"
)

// Accounts wires the account routes.
type Accounts struct {
	Store     *store.Accounts
	Creds     *store.Credentials
	Endpoints *store.Endpoints
	Demo      *demo.Service
	// Now returns the current wall-clock ISO string (for updated_at).
	Now func() string
	// OnDeleted fires after an admin hard-deletes an account (in-memory teardown
	// + Hydra session revoke), mirroring the Node lifecycle bus.
	OnDeleted func(accountID string)
}

func (a *Accounts) Mount(r chi.Router) {
	r.Get("/api/auth/me", a.me)
	r.Put("/api/auth/me", a.updateMe)
	r.Get("/api/accounts", a.list)
	r.Delete("/api/accounts/{id}", a.delete)
	r.Get("/api/accounts/export-seed", a.exportSeed)
}

func (a *Accounts) me(w http.ResponseWriter, r *http.Request) {
	acct, err := a.Store.Get(r.Context(), accountID(r))
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	if acct == nil {
		writeErr(w, 401, "Account not found")
		return
	}
	writeJSON(w, 200, map[string]any{
		"id": acct.ID, "name": acct.Name, "isAdmin": acct.IsAdmin,
		"showDemoEndpoints":      acct.ShowDemoEndpoints,
		"demoEndpointsAvailable": !a.Demo.IsEmpty(),
	})
}

func (a *Accounts) updateMe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name              *string `json:"name"`
		ShowDemoEndpoints *bool   `json:"showDemoEndpoints"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Name != nil {
		trimmed := strings.TrimSpace(*body.Name)
		if trimmed == "" {
			writeErr(w, 400, "Name cannot be empty")
			return
		}
		body.Name = &trimmed
	}
	if err := a.Store.UpdateSelf(r.Context(), accountID(r), body.Name, body.ShowDemoEndpoints, a.Now()); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "updated"})
}

func (a *Accounts) list(w http.ResponseWriter, r *http.Request) {
	if !a.Store.IsAdmin(r.Context(), accountID(r)) {
		writeErr(w, 403, "Admin access required")
		return
	}
	all, err := a.Store.List(r.Context())
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	out := make([]map[string]any, 0, len(all))
	for _, acct := range all {
		out = append(out, map[string]any{
			"id": acct.ID, "name": acct.Name, "isAdmin": acct.IsAdmin, "enabled": acct.Enabled,
			"maxSessions": acct.MaxSessions, "lastUsedAt": acct.LastUsedAt, "createdAt": acct.CreatedAt,
		})
	}
	writeJSON(w, 200, map[string]any{"accounts": out})
}

func (a *Accounts) delete(w http.ResponseWriter, r *http.Request) {
	caller := accountID(r)
	if !a.Store.IsAdmin(r.Context(), caller) {
		writeErr(w, 403, "Admin access required")
		return
	}
	target := chi.URLParam(r, "id")
	if target == caller {
		writeErr(w, 400, "Cannot delete your own account")
		return
	}
	if a.Store.IsAdmin(r.Context(), target) {
		writeErr(w, 400, "Cannot delete the admin account")
		return
	}
	if err := a.Store.Delete(r.Context(), target); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	if a.OnDeleted != nil {
		a.OnDeleted(target)
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

func (a *Accounts) exportSeed(w http.ResponseWriter, r *http.Request) {
	adminID := accountID(r)
	if !a.Store.IsAdmin(r.Context(), adminID) {
		writeErr(w, 403, "Admin access required")
		return
	}
	passkeys, err := a.Creds.ExportSeed(r.Context(), adminID)
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	eps, err := a.Endpoints.ListForAccount(r.Context(), adminID)
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	seedEps := make([]store.SeedEndpoint, 0, len(eps))
	for _, e := range eps {
		seedEps = append(seedEps, store.SeedEndpoint{
			Label: e.Label,
			Address: config.FormatEndpointAddress(config.EndpointAddress{
				Username: e.Username, Host: e.Host, Port: int(e.Port),
			}),
			AgentForward: e.AgentForward,
		})
	}
	writeJSON(w, 200, store.SeedExport{Passkeys: passkeys, Endpoints: seedEps})
}
