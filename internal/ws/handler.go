// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package ws

import (
	"net/http"

	"github.com/coder/websocket"

	"github.com/rado0x54/shellwatch/internal/auth"
)

// Handler returns the /ws upgrade handler. The bearer gate (upstream
// middleware) has already authenticated the request via the
// Sec-WebSocket-Protocol token; here we negotiate the sentinel subprotocol
// back (never the token) and run the hub's read loop.
func (h *Hub) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.PrincipalFrom(r.Context())
		if !ok {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// Negotiate only the sentinel; the token subprotocol is never
			// echoed back.
			Subprotocols: []string{auth.WSBearerSubprotocol},
		})
		if err != nil {
			return
		}
		// Disable coder/websocket's default read limit — terminal output can
		// exceed 32 KiB and we frame our own messages.
		c.SetReadLimit(-1)
		h.Serve(r.Context(), c, principal.AccountID)
	}
}
