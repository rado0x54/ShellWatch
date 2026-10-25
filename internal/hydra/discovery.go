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
		writeJSON(w, asMetadata{
			Issuer:                        hydraPub,
			AuthorizationEndpoint:         hydraPub + "/oauth2/auth",
			TokenEndpoint:                 hydraPub + "/oauth2/token",
			RegistrationEndpoint:          ext() + "/api/hydra/register",
			JwksURI:                       hydraPub + "/.well-known/jwks.json",
			RevocationEndpoint:            hydraPub + "/oauth2/revoke",
			ResponseTypesSupported:        []string{"code"},
			GrantTypesSupported:           []string{"authorization_code", "refresh_token"},
			CodeChallengeMethodsSupported: []string{"S256"},
			TokenEndpointAuthMethodsSupported: []string{
				"none", "client_secret_basic", "client_secret_post",
			},
			ScopesSupported: scopes,
		})
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
