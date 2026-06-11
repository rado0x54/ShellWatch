// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Idempotently provision the first-party PUBLIC SPA client in Hydra on boot
 * (#217) so the web-UI authorization-code + PKCE flow works without a manual
 * `hydra create client` step. Public client — no secret, PKCE-enforced by
 * Hydra. Safe to run every startup (create-or-update).
 */
import { UI_SCOPE, type HydraConfig } from "../config/index.js";
import type { HydraAdminClient } from "./admin-client.js";
import type { HydraOAuth2Client } from "./types.js";

export async function ensureSpaClient(admin: HydraAdminClient, hydra: HydraConfig): Promise<void> {
  const redirectUri = hydra.spa.redirectUri;
  if (!redirectUri)
    throw new Error("hydra.spa.redirectUri must be resolved before ensureSpaClient");

  const desired: HydraOAuth2Client = {
    client_id: hydra.spa.clientId,
    client_name: "ShellWatch Web UI",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    // openid → subject/id_token; offline → refresh token for silent renew;
    // ui → the scope the bearer gate requires for ShellWatch's own /api + /ws.
    scope: `openid offline ${UI_SCOPE}`,
    redirect_uris: [redirectUri],
    // Public client (browser) — no secret; Hydra enforces PKCE.
    token_endpoint_auth_method: "none",
  };

  const existing = await admin.getClient(hydra.spa.clientId);
  if (!existing) {
    await admin.createClient(desired);
  } else {
    await admin.updateClient(hydra.spa.clientId, desired);
  }
}
