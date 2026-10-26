// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Notification log REST (#252): the keyset-paginated account notification
// stream behind the /notifications page. Read-only — notifications are
// produced server-side (internal/notify) and never written by clients.
package rest

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/rado0x54/shellwatch/internal/notify"
)

// Notifications wires the notification-log read route.
type Notifications struct {
	Svc *notify.Service
}

func (n *Notifications) Mount(r chi.Router) {
	r.Get("/api/notifications", n.list)
}

func (n *Notifications) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, err := n.Svc.List(r.Context(), accountID(r), q.Get("cursor"), parseLimit(q.Get("limit")))
	if err != nil {
		writeErr(w, 500, "internal error")
		return
	}
	writeJSON(w, 200, page)
}
