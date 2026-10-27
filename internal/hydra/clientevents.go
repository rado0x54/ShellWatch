// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// The registration event both client-onboarding paths emit — mediated DCR
// (POST /api/hydra/register) and CIMD resolution (GET /api/hydra/authorize).
//
// This package deliberately does not know where the events go. Both paths run
// entirely before any account is identified, so the record cannot live in the
// account-scoped audit tables; the composition root supplies a sink that
// writes the non-account-scoped registration log (internal/audit,
// migration 00004). A nil sink simply drops events.
package hydra

import "net/http"

// Registration origins (mirrored by audit.Origin*).
const (
	ClientOriginDCR  = "dcr"
	ClientOriginCIMD = "cimd"
)

// Registration events (mirrored by audit.Event*). #255 adds "blocked".
const (
	ClientEventRegistered = "registered"
	ClientEventRefreshed  = "refreshed"
	ClientEventRejected   = "rejected"
)

// ClientEvent is one onboarding outcome, denormalized at emit time so the log
// never has to be re-read against a client that may since have changed.
type ClientEvent struct {
	// ClientID is Hydra's client_id: a UUID for DCR, the Client Identifier URL
	// for CIMD. It is the link to Hydra's own data model.
	ClientID string
	Origin   string
	Event    string
	// ClientName is empty on a rejection (no document was accepted).
	ClientName string
	// MetadataHost is the CIMD Client Identifier URL's hostname — the identity
	// cue draft-ietf-oauth-client-id-metadata-document-02 §9.1 wants surfaced.
	// Empty for DCR.
	MetadataHost string
	AuthMethod   string
	RedirectURIs []string
	Scope        string
	// Reason carries the cause for a rejection, or what changed on a refresh.
	Reason string
}

// ClientEventSink receives registration events. The request is passed so the
// sink can resolve the peer address with the server's trust-proxy policy.
type ClientEventSink func(r *http.Request, ev ClientEvent)
