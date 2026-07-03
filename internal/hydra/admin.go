// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package hydra is the Ory Hydra glue (port of src/hydra/): thin admin-API
// client, cached bearer introspection, discovery documents, and — in later
// Phase 2 slices — the passkey login/consent providers and mediated DCR.
//
// The admin API is unauthenticated by design and MUST be reachable only over
// a trusted network (docs/deployment.md).
package hydra

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"encoding/json"
)

// Introspection is the RFC 7662 response subset (src/hydra/types.ts).
type Introspection struct {
	Active   bool   `json:"active"`
	Sub      string `json:"sub"`
	Scope    string `json:"scope"`
	ClientID string `json:"client_id"`
	// TokenUse is Hydra's discriminator ("access_token" | "refresh_token");
	// the bearer resolver only honors access tokens.
	TokenUse string   `json:"token_use"`
	Exp      int64    `json:"exp"`
	Aud      []string `json:"aud"`
}

// Introspector is the slice of the admin client the bearer resolver needs;
// tests inject fakes.
type Introspector interface {
	Introspect(ctx context.Context, token string) (Introspection, error)
}

// APIError carries the Hydra admin response status + body.
type APIError struct {
	Status int
	Body   string
	Msg    string
}

func (e *APIError) Error() string { return fmt.Sprintf("%s (status %d)", e.Msg, e.Status) }

// AdminClient is the production Introspector (grows accept/reject login/
// consent, client CRUD, and session revocation in later slices).
type AdminClient struct {
	base string
	http *http.Client
}

func NewAdminClient(adminURL string, client *http.Client) *AdminClient {
	if client == nil {
		client = http.DefaultClient
	}
	return &AdminClient{base: strings.TrimRight(adminURL, "/"), http: client}
}

// Introspect implements RFC 7662 against Hydra's admin endpoint
// (admin-client.ts introspect).
func (c *AdminClient) Introspect(ctx context.Context, token string) (Introspection, error) {
	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/admin/oauth2/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		return Introspection{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := c.http.Do(req)
	if err != nil {
		return Introspection{}, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return Introspection{}, err
	}
	if res.StatusCode != http.StatusOK {
		return Introspection{}, &APIError{Status: res.StatusCode, Body: string(body),
			Msg: fmt.Sprintf("Hydra introspect -> %d", res.StatusCode)}
	}
	var ins Introspection
	if err := json.Unmarshal(body, &ins); err != nil {
		return Introspection{}, err
	}
	return ins, nil
}

// adminJSON performs a JSON admin request and decodes the response into out.
func (c *AdminClient) adminJSON(ctx context.Context, method, path string, in, out any) error {
	var reader io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		reader = strings.NewReader(string(raw))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return &APIError{Status: res.StatusCode, Body: string(body),
			Msg: fmt.Sprintf("Hydra admin %s %s -> %d", method, path, res.StatusCode)}
	}
	if out != nil && len(body) > 0 {
		return json.Unmarshal(body, out)
	}
	return nil
}

// AcceptLoginRequest accepts a login challenge (admin-client.ts).
func (c *AdminClient) AcceptLoginRequest(ctx context.Context, challenge string, body AcceptLogin) (Redirect, error) {
	var r Redirect
	err := c.adminJSON(ctx, http.MethodPut,
		"/admin/oauth2/auth/requests/login/accept?login_challenge="+url.QueryEscape(challenge), body, &r)
	return r, err
}

// GetLoginRequest fetches a login challenge.
func (c *AdminClient) GetLoginRequest(ctx context.Context, challenge string) (LoginRequest, error) {
	var lr LoginRequest
	err := c.adminJSON(ctx, http.MethodGet,
		"/admin/oauth2/auth/requests/login?login_challenge="+url.QueryEscape(challenge), nil, &lr)
	return lr, err
}

// GetConsentRequest fetches a consent challenge.
func (c *AdminClient) GetConsentRequest(ctx context.Context, challenge string) (ConsentRequest, error) {
	var cr ConsentRequest
	err := c.adminJSON(ctx, http.MethodGet,
		"/admin/oauth2/auth/requests/consent?consent_challenge="+url.QueryEscape(challenge), nil, &cr)
	return cr, err
}

// AcceptConsentRequest accepts a consent challenge.
func (c *AdminClient) AcceptConsentRequest(ctx context.Context, challenge string, body AcceptConsent) (Redirect, error) {
	var r Redirect
	err := c.adminJSON(ctx, http.MethodPut,
		"/admin/oauth2/auth/requests/consent/accept?consent_challenge="+url.QueryEscape(challenge), body, &r)
	return r, err
}

// ListConsentSessions lists a subject's active consent grants.
func (c *AdminClient) ListConsentSessions(ctx context.Context, subject string) ([]ConsentSession, error) {
	var out []ConsentSession
	err := c.adminJSON(ctx, http.MethodGet,
		"/admin/oauth2/auth/sessions/consent?subject="+url.QueryEscape(subject), nil, &out)
	return out, err
}

// RevokeConsentSessions deletes a subject's consent sessions (optionally scoped
// to one client).
func (c *AdminClient) RevokeConsentSessions(ctx context.Context, subject, clientID string) error {
	path := "/admin/oauth2/auth/sessions/consent?subject=" + url.QueryEscape(subject)
	if clientID != "" {
		path += "&client=" + url.QueryEscape(clientID)
	}
	err := c.adminJSON(ctx, http.MethodDelete, path, nil, nil)
	if apiErr, ok := err.(*APIError); ok && apiErr.Status == http.StatusNotFound {
		return nil
	}
	return err
}

// RevokeLoginSessions deletes a subject's login (SSO) sessions.
func (c *AdminClient) RevokeLoginSessions(ctx context.Context, subject string) error {
	err := c.adminJSON(ctx, http.MethodDelete,
		"/admin/oauth2/auth/sessions/login?subject="+url.QueryEscape(subject), nil, nil)
	if apiErr, ok := err.(*APIError); ok && apiErr.Status == http.StatusNotFound {
		return nil
	}
	return err
}

// GetLogoutRequest fetches a logout challenge.
func (c *AdminClient) GetLogoutRequest(ctx context.Context, challenge string) (LogoutRequest, error) {
	var lr LogoutRequest
	err := c.adminJSON(ctx, http.MethodGet,
		"/admin/oauth2/auth/requests/logout?logout_challenge="+url.QueryEscape(challenge), nil, &lr)
	return lr, err
}

// AcceptLogoutRequest accepts a logout challenge.
func (c *AdminClient) AcceptLogoutRequest(ctx context.Context, challenge string) (Redirect, error) {
	var r Redirect
	err := c.adminJSON(ctx, http.MethodPut,
		"/admin/oauth2/auth/requests/logout/accept?logout_challenge="+url.QueryEscape(challenge), nil, &r)
	return r, err
}

// RejectLogoutRequest rejects a logout challenge (CSRF guard).
func (c *AdminClient) RejectLogoutRequest(ctx context.Context, challenge string) error {
	return c.adminJSON(ctx, http.MethodPut,
		"/admin/oauth2/auth/requests/logout/reject?logout_challenge="+url.QueryEscape(challenge), nil, nil)
}

// CreateClient registers an OAuth2 client (POST /admin/clients).
func (c *AdminClient) CreateClient(ctx context.Context, client OAuth2Client) (OAuth2Client, error) {
	var out OAuth2Client
	err := c.adminJSON(ctx, http.MethodPost, "/admin/clients", client, &out)
	return out, err
}

// GetClient fetches a client, returning nil on 404.
func (c *AdminClient) GetClient(ctx context.Context, clientID string) (*OAuth2Client, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.base+"/admin/clients/"+url.PathEscape(clientID), nil)
	if err != nil {
		return nil, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, &APIError{Status: res.StatusCode, Body: string(body),
			Msg: fmt.Sprintf("Hydra admin GET client -> %d", res.StatusCode)}
	}
	var out OAuth2Client
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateClient replaces a client (PUT /admin/clients/{id}).
func (c *AdminClient) UpdateClient(ctx context.Context, clientID string, client OAuth2Client) (OAuth2Client, error) {
	var out OAuth2Client
	err := c.adminJSON(ctx, http.MethodPut, "/admin/clients/"+url.PathEscape(clientID), client, &out)
	return out, err
}

var _ Admin = (*AdminClient)(nil)
