// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Hydra admin request/response types (subset of src/hydra/types.ts) used by
// the login provider + mediated DCR.
package hydra

import "context"

// Redirect is the {redirect_to} response from accept/reject flows.
type Redirect struct {
	RedirectTo string `json:"redirect_to"`
}

// AcceptLogin is the body for accepting a login challenge (HydraAcceptLogin).
type AcceptLogin struct {
	Subject     string         `json:"subject"`
	Remember    bool           `json:"remember,omitempty"`
	RememberFor int            `json:"remember_for,omitempty"`
	Context     map[string]any `json:"context,omitempty"`
}

// OAuth2Client is the subset of Hydra's client object we create/read/update.
type OAuth2Client struct {
	ClientID                string   `json:"client_id,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// Admin is the full admin surface the providers + DCR + ensureSpaClient need.
type Admin interface {
	Introspector
	AcceptLoginRequest(ctx context.Context, challenge string, body AcceptLogin) (Redirect, error)
	CreateClient(ctx context.Context, client OAuth2Client) (OAuth2Client, error)
	GetClient(ctx context.Context, clientID string) (*OAuth2Client, error)
	UpdateClient(ctx context.Context, clientID string, client OAuth2Client) (OAuth2Client, error)
}
