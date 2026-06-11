// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Minimal typed views of the Ory Hydra admin + OAuth2 API surface ShellWatch
 * actually uses (#217). These are intentionally partial — Hydra returns far
 * more fields than we model. Field names mirror Hydra's JSON wire format.
 */

/** Hydra login request (GET /admin/oauth2/auth/requests/login). */
export interface HydraLoginRequest {
  challenge: string;
  /**
   * True when Hydra already has an authenticated session for a subject and is
   * asking us to confirm it. When set, accept with `subject` unchanged and
   * skip the passkey ceremony.
   */
  skip: boolean;
  subject: string;
  client: HydraOAuth2Client;
  request_url: string;
  requested_scope: string[];
  requested_access_token_audience: string[];
}

/** Hydra consent request (GET /admin/oauth2/auth/requests/consent). */
export interface HydraConsentRequest {
  challenge: string;
  skip: boolean;
  subject: string;
  client: HydraOAuth2Client;
  requested_scope: string[];
  requested_access_token_audience: string[];
}

/** Body for accepting a login challenge. */
export interface HydraAcceptLogin {
  subject: string;
  remember?: boolean;
  remember_for?: number;
  acr?: string;
  context?: Record<string, unknown>;
}

/** Body for accepting a consent challenge. */
export interface HydraAcceptConsent {
  grant_scope: string[];
  grant_access_token_audience?: string[];
  remember?: boolean;
  remember_for?: number;
  session?: {
    access_token?: Record<string, unknown>;
    id_token?: Record<string, unknown>;
  };
}

/** Hydra redirect response wrapper ({ redirect_to }). */
export interface HydraRedirect {
  redirect_to: string;
}

/** Create payload — like HydraOAuth2Client but client_id is server-assignable. */
export type HydraOAuth2ClientCreate = Omit<HydraOAuth2Client, "client_id"> & { client_id?: string };

/** Subset of Hydra's OAuth2Client we read/write. */
export interface HydraOAuth2Client {
  client_id: string;
  client_name?: string;
  client_secret?: string;
  grant_types?: string[];
  response_types?: string[];
  scope?: string;
  redirect_uris?: string[];
  token_endpoint_auth_method?: string;
  metadata?: Record<string, unknown>;
  client_secret_expires_at?: number;
}

/** RFC 7662 introspection response (subset). */
export interface HydraIntrospection {
  active: boolean;
  sub?: string;
  scope?: string;
  client_id?: string;
  token_type?: string;
  exp?: number;
  aud?: string[];
}

/** Token endpoint response (subset of RFC 6749 §5.1). */
export interface HydraTokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
}
