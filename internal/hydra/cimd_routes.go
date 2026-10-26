// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// The authorization front door: GET /api/hydra/authorize, advertised as
// `authorization_endpoint` in the AS metadata.
//
// Hydra rejects a URL client_id as an unknown client before ShellWatch would
// ever see the request, so CIMD needs somewhere to resolve the document first.
// This endpoint does exactly that and nothing else — it never issues a code,
// never touches a session, and hands every request on to Hydra's /oauth2/auth
// with the query string intact. A non-URL client_id (the SPA, every DCR
// client) is passed straight through, so the existing flows are untouched.
package hydra

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
)

// FrontDoorParams wires GET /api/hydra/authorize.
type FrontDoorParams struct {
	// Resolver is nil when CIMD is disabled; every request is then a
	// passthrough and a URL client_id reaches Hydra, which rejects it.
	Resolver *CIMDResolver
	// HydraAuthorizeURL is Hydra's real authorization endpoint.
	HydraAuthorizeURL string
	// OnEvent, when set, records an audit event for each CIMD outcome.
	OnEvent func(r *http.Request, ev CIMDEvent)
}

// CIMDEvent is what the front door reports to the audit log.
type CIMDEvent struct {
	// Type is one of the oauth-client-* audit event types.
	Type string
	// ClientID is the Client Identifier URL.
	ClientID string
	// Host is the client_id's hostname — the identity cue the draft wants
	// surfaced (§9.1), and the one field worth indexing.
	Host string
	// AuthMethod is the resolved token_endpoint_auth_method, when known.
	AuthMethod string
	// Reason carries the rejection cause for oauth-client-metadata-rejected.
	Reason string
}

// Audit event types written by the front door.
const (
	EventClientDiscovered      = "oauth-client-discovered"
	EventClientMetadataChanged = "oauth-client-metadata-changed"
	EventClientRejected        = "oauth-client-metadata-rejected"
)

// MountFrontDoor registers GET /api/hydra/authorize.
func MountFrontDoor(r chi.Router, p FrontDoorParams) {
	r.Get("/api/hydra/authorize", p.handleAuthorize)
}

func (p FrontDoorParams) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")

	// Pass through anything that is not CIMD-shaped: the first-party SPA, every
	// DCR client, and a missing client_id (Hydra owns that error). RawQuery is
	// forwarded verbatim so Hydra sees byte-for-byte what the client sent.
	if p.Resolver == nil || !IsClientIDURL(clientID) {
		p.redirectToHydra(w, r)
		return
	}

	res, err := p.Resolver.Resolve(r.Context(), clientID, q.Get("redirect_uri"), q.Get("scope"))
	if err != nil {
		p.fail(w, r, clientID, err)
		return
	}

	if p.OnEvent != nil {
		ev := CIMDEvent{
			Type:       EventClientDiscovered,
			ClientID:   clientID,
			Host:       hostOf(clientID),
			AuthMethod: res.Doc.TokenEndpointAuthMethod,
		}
		if res.MaterialChange {
			ev.Type = EventClientMetadataChanged
			ev.Reason = "authentication keys or method changed"
		}
		if res.FirstSeen || res.MaterialChange {
			p.OnEvent(r, ev)
		}
	}
	p.redirectToHydra(w, r)
}

// redirectToHydra forwards to Hydra's /oauth2/auth with the request's query
// string unchanged.
func (p FrontDoorParams) redirectToHydra(w http.ResponseWriter, r *http.Request) {
	target := p.HydraAuthorizeURL
	if raw := r.URL.RawQuery; raw != "" {
		target += "?" + raw
	}
	// 303: this is a GET-to-GET hand-off and must never be cached, since the
	// resolution behind it can change.
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// fail renders or redirects an OAuth error.
//
// A redirect carrying error+state is only safe once the requested redirect_uri
// has been checked against the document — otherwise an attacker picks the
// destination. Everything that fails before that check renders the error page
// instead.
func (p FrontDoorParams) fail(w http.ResponseWriter, r *http.Request, clientID string, err error) {
	re, ok := err.(*ResolveError)
	if !ok {
		re = &ResolveError{Code: "server_error", Description: err.Error()}
	}
	if p.OnEvent != nil {
		p.OnEvent(r, CIMDEvent{
			Type:     EventClientRejected,
			ClientID: clientID,
			Host:     hostOf(clientID),
			Reason:   re.Description,
		})
	}

	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	if re.RedirectValidated && redirectURI != "" {
		if u, perr := url.Parse(redirectURI); perr == nil {
			rq := u.Query()
			rq.Set("error", re.Code)
			rq.Set("error_description", re.Description)
			if state := q.Get("state"); state != "" {
				rq.Set("state", state)
			}
			u.RawQuery = rq.Encode()
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, u.String(), http.StatusSeeOther)
			return
		}
	}
	writeHTML(w, http.StatusBadRequest, renderErrorPage(re.Code, re.Description))
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
