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
	// CreatedAt is Hydra's DCR registration timestamp (read-only; surfaced by
	// /api/auth/sessions).
	CreatedAt string `json:"created_at,omitempty"`
}

// LoginRequest is the GET login-challenge response (subset).
type LoginRequest struct {
	Challenge string `json:"challenge"`
	Skip      bool   `json:"skip"`
	Subject   string `json:"subject"`
}

// ConsentRequest is the GET consent-challenge response (subset).
type ConsentRequest struct {
	Challenge                    string         `json:"challenge"`
	Skip                         bool           `json:"skip"`
	Subject                      string         `json:"subject"`
	Client                       OAuth2Client   `json:"client"`
	RequestedScope               []string       `json:"requested_scope"`
	RequestedAccessTokenAudience []string       `json:"requested_access_token_audience"`
	Context                      map[string]any `json:"context"`
}

// AcceptConsent is the body for accepting a consent challenge.
type AcceptConsent struct {
	GrantScope               []string       `json:"grant_scope"`
	GrantAccessTokenAudience []string       `json:"grant_access_token_audience,omitempty"`
	Remember                 bool           `json:"remember,omitempty"`
	RememberFor              int            `json:"remember_for,omitempty"`
	Session                  map[string]any `json:"session,omitempty"`
}

// LogoutRequest is the GET logout-challenge response (subset).
type LogoutRequest struct {
	Challenge string `json:"challenge"`
	Subject   string `json:"subject"`
	ClientID  string `json:"client,omitempty"`
}

// ConsentSession is one authorized-client grant (listConsentSessions row).
type ConsentSession struct {
	GrantScope     []string `json:"grant_scope"`
	HandledAt      string   `json:"handled_at"`
	ConsentRequest *struct {
		Client OAuth2Client `json:"client"`
	} `json:"consent_request"`
}

// Admin is the full admin surface the providers + DCR + ensureSpaClient + the
// account-session routes need.
type Admin interface {
	Introspector
	AcceptLoginRequest(ctx context.Context, challenge string, body AcceptLogin) (Redirect, error)
	GetLoginRequest(ctx context.Context, challenge string) (LoginRequest, error)
	GetConsentRequest(ctx context.Context, challenge string) (ConsentRequest, error)
	AcceptConsentRequest(ctx context.Context, challenge string, body AcceptConsent) (Redirect, error)
	ListConsentSessions(ctx context.Context, subject string) ([]ConsentSession, error)
	RevokeConsentSessions(ctx context.Context, subject, clientID string) error
	RevokeLoginSessions(ctx context.Context, subject string) error
	CreateClient(ctx context.Context, client OAuth2Client) (OAuth2Client, error)
	GetClient(ctx context.Context, clientID string) (*OAuth2Client, error)
	UpdateClient(ctx context.Context, clientID string, client OAuth2Client) (OAuth2Client, error)
}
