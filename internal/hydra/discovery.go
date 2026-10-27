// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Discovery documents (port of the discovery section of src/hydra/routes.ts):
// RFC 9728 protected-resource docs per scope plus a blended RFC 8414 AS
// metadata doc that points authorization/token at Hydra but advertises
// ShellWatch's mediated registration_endpoint. Bodies are pinned by the
// discovery-* goldens (compared decoded, so key order is not contractual).
package hydra

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

type DiscoveryParams struct {
	// ExternalURL is read at request time (tests pin it after boot).
	ExternalURL       func() string
	HydraPublicURL    string
	AgentProxyEnabled bool
	// CimdEnabled points authorization_endpoint at ShellWatch's front door and
	// advertises client_id_metadata_document_supported.
	//
	// Turning it off is an operator kill switch, not a hand-off: Hydra cannot
	// resolve a metadata document, so authorization goes straight to
	// /oauth2/auth and a URL client_id stops working entirely (Hydra rejects it
	// as an unknown client). Pre-registered and DCR clients are unaffected
	// either way.
	CimdEnabled bool
}

type resourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	// offline_access advertised so clients request it -> Hydra issues a
	// refresh token (silent renewal instead of a re-auth redirect).
	ScopesSupported []string `json:"scopes_supported"`
}

type asMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	// ClientIDMetadataDocumentSupported is draft §6. Omitted entirely when
	// CIMD is off, rather than advertised as false.
	ClientIDMetadataDocumentSupported bool `json:"client_id_metadata_document_supported,omitempty"`
}

// MountDiscovery registers the /.well-known documents on the router.
func MountDiscovery(r chi.Router, p DiscoveryParams) {
	ext := func() string { return strings.TrimRight(p.ExternalURL(), "/") }
	hydraPub := strings.TrimRight(p.HydraPublicURL, "/")

	resource := func(scope, path string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, resourceMetadata{
				Resource:               ext() + path,
				AuthorizationServers:   []string{ext()},
				BearerMethodsSupported: []string{"header"},
				ScopesSupported:        []string{scope, "offline_access"},
			})
		}
	}

	// The bare path is a convenience alias for the MCP doc (contract item I —
	// preserved deliberately).
	r.Get("/.well-known/oauth-protected-resource", resource("mcp", "/mcp"))
	r.Get("/.well-known/oauth-protected-resource/mcp", resource("mcp", "/mcp"))
	if p.AgentProxyEnabled {
		r.Get("/.well-known/oauth-protected-resource/agent-proxy", resource("agent", "/agent-proxy"))
	}

	r.Get("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		// BEARER_SCOPES order is alphabetical (agent, mcp) in Node; agent is
		// filtered out when the proxy is disabled.
		scopes := []string{}
		if p.AgentProxyEnabled {
			scopes = append(scopes, "agent")
		}
		scopes = append(scopes, "mcp", "offline_access")
		// With CIMD on, authorization goes through ShellWatch's front door:
		// Hydra cannot resolve a URL client_id itself. Everything else still
		// points at Hydra, so token/refresh/revoke are untouched.
		authorizeEndpoint := hydraPub + "/oauth2/auth"
		if p.CimdEnabled {
			authorizeEndpoint = ext() + "/api/hydra/authorize"
		}
		// ShellWatch never issues a client secret — not via DCR, not via CIMD
		// (draft §4.1 forbids it outright) — so the shared-secret methods
		// Hydra would otherwise accept are not advertised.
		authMethods := []string{"none", "private_key_jwt"}
		writeJSON(w, asMetadata{
			Issuer:                            hydraPub,
			AuthorizationEndpoint:             authorizeEndpoint,
			TokenEndpoint:                     hydraPub + "/oauth2/token",
			RegistrationEndpoint:              ext() + "/api/hydra/register",
			JwksURI:                           hydraPub + "/.well-known/jwks.json",
			RevocationEndpoint:                hydraPub + "/oauth2/revoke",
			ResponseTypesSupported:            []string{"code"},
			GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
			CodeChallengeMethodsSupported:     []string{"S256"},
			TokenEndpointAuthMethodsSupported: authMethods,
			ScopesSupported:                   scopes,
			ClientIDMetadataDocumentSupported: p.CimdEnabled,
		})
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
