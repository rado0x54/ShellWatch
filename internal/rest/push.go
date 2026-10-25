// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Web Push subscription REST (/api/push/subscribe) — port of push.ts. Pinned by
// push-subscribe / push-unsubscribe goldens.
package rest

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/store"
)

// Push wires the push subscription routes.
type Push struct {
	Store *store.PushSubs
	// AllowedEndpoint validates the push service origin (SSRF guard); nil => allow.
	AllowedEndpoint func(endpoint string) bool
	NewID           func() string
}

func (p *Push) Mount(r chi.Router) {
	r.Post("/api/push/subscribe", p.subscribe)
	r.Delete("/api/push/subscribe", p.unsubscribe)
}

func (p *Push) subscribe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Endpoint string `json:"endpoint"`
		Keys     struct {
			P256dh string `json:"p256dh"`
			Auth   string `json:"auth"`
		} `json:"keys"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Endpoint == "" || body.Keys.P256dh == "" || body.Keys.Auth == "" {
		writeErr(w, 400, "Invalid subscription: endpoint, keys.p256dh, and keys.auth are required")
		return
	}
	if p.AllowedEndpoint != nil && !p.AllowedEndpoint(body.Endpoint) {
		writeErr(w, 400, "endpoint is not a recognized push service")
		return
	}
	res, err := p.Store.Upsert(r.Context(), accountID(r), body.Endpoint, body.Keys.P256dh, body.Keys.Auth, p.NewID())
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	if res.Conflict {
		writeErr(w, 409, "endpoint already registered to a different account")
		return
	}
	writeJSON(w, 200, map[string]string{"id": res.ID})
}

func (p *Push) unsubscribe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Endpoint string `json:"endpoint"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Endpoint == "" {
		writeErr(w, 400, "endpoint is required")
		return
	}
	if err := p.Store.Delete(r.Context(), accountID(r), body.Endpoint); err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
