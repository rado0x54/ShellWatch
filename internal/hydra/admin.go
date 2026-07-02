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
