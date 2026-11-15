// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package ws

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/rado0x54/shellwatch/internal/apierr"
	"github.com/rado0x54/shellwatch/internal/auth"
	"github.com/rado0x54/shellwatch/internal/realip"
)

// Handler returns the /ws upgrade handler. The bearer gate (upstream
// middleware) has already authenticated the request via the
// Sec-WebSocket-Protocol token; here we negotiate the sentinel subprotocol
// back (never the token) and run the hub's read loop.
// MaxInboundMessageBytes caps one client→server /ws message. The largest
// legitimate frame is a terminal:input paste; 1 MiB leaves ample room for
// that while stopping a single frame from forcing an unbounded allocation.
const MaxInboundMessageBytes = 1 << 20

func (h *Hub) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.PrincipalFrom(r.Context())
		if !ok {
			// Defensive: the bearer gate 401s unauthenticated /ws upgrades
			// before this handler runs.
			apierr.Write(w, http.StatusUnauthorized, "unauthenticated")
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
		// The read limit bounds INBOUND frames only (input/resize/control);
		// outbound terminal output is unaffected. An oversized frame closes
		// the connection with 1009 instead of buffering it whole.
		c.SetReadLimit(MaxInboundMessageBytes)
		start := time.Now()
		ip := realip.FromRequest(r)
		slog.Info("ws: connected", "account", principal.AccountID, "sourceIp", ip)
		err = h.Serve(r.Context(), c, principal.AccountID)
		slog.Info("ws: disconnected", "account", principal.AccountID, "sourceIp", ip,
			"duration", time.Since(start).Round(time.Second), "reason", disconnectReason(err))
	}
}

// disconnectReason condenses the read-loop error that ended a connection:
// the peer's close code when it sent one, otherwise the error text.
func disconnectReason(err error) string {
	if err == nil {
		return "server"
	}
	if code := websocket.CloseStatus(err); code != -1 {
		return "close " + code.String()
	}
	if errors.Is(err, context.Canceled) {
		return "server"
	}
	return err.Error()
}
