// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Bridge from the OAuth client registration events internal/hydra emits to the
// non-account-scoped log internal/audit writes (#242).
//
// internal/hydra must not import the audit writer (that would be an upward
// import), and internal/audit must not import hydra for the same reason — so
// the two field-identical structs meet here, in the one package that already
// knows both.
package httpserver

import (
	"context"
	"net/http"

	"github.com/rado0x54/shellwatch/internal/audit"
	"github.com/rado0x54/shellwatch/internal/hydra"
	"github.com/rado0x54/shellwatch/internal/realip"
)

// ClientLogRecorder appends one registration event (satisfied by
// *audit.OAuthClients).
type ClientLogRecorder interface {
	Record(ctx context.Context, ev audit.OAuthClientEvent)
}

// clientEventSink adapts a recorder to the sink internal/hydra calls. A nil
// recorder yields a nil sink, which the emitters skip.
func clientEventSink(log ClientLogRecorder) hydra.ClientEventSink {
	if log == nil {
		return nil
	}
	return func(r *http.Request, ev hydra.ClientEvent) {
		log.Record(r.Context(), audit.OAuthClientEvent{
			ClientID:     ev.ClientID,
			Origin:       ev.Origin,
			Event:        ev.Event,
			ClientName:   ev.ClientName,
			MetadataHost: ev.MetadataHost,
			AuthMethod:   ev.AuthMethod,
			RedirectURIs: ev.RedirectURIs,
			Scope:        ev.Scope,
			Reason:       ev.Reason,
			// Resolved under the server's trustProxy policy by the realip
			// middleware, so a proxied deployment records the real peer.
			SourceIP: realip.FromRequest(r),
		})
	}
}
