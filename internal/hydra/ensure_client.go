// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Idempotent SPA client provisioning (port of src/hydra/ensure-client.ts):
// create-or-update the first-party public PKCE client on boot so the web-UI
// auth-code flow works without a manual `hydra create client`.
package hydra

import (
	"context"
	"fmt"

	"github.com/rado0x54/shellwatch/internal/auth"
)

// EnsureSpaClient provisions the SPA client. redirectURI must be resolved
// (the loader derives it from externalURL).
func EnsureSpaClient(ctx context.Context, admin Admin, clientID, redirectURI string) error {
	if redirectURI == "" {
		return fmt.Errorf("hydra.spa.redirectUri must be resolved before EnsureSpaClient")
	}
	desired := OAuth2Client{
		ClientID:      clientID,
		ClientName:    "ShellWatch Web UI",
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		// openid -> subject/id_token; offline_access -> refresh token;
		// ui -> the scope the bearer gate requires for /api + /ws.
		Scope:                   "openid offline_access " + auth.UIScope,
		RedirectURIs:            []string{redirectURI},
		TokenEndpointAuthMethod: "none",
	}
	existing, err := admin.GetClient(ctx, clientID)
	if err != nil {
		return err
	}
	if existing == nil {
		_, err = admin.CreateClient(ctx, desired)
		return err
	}
	_, err = admin.UpdateClient(ctx, clientID, desired)
	return err
}
