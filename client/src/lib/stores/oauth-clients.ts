// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * OAuth client registration log (#242): how each MCP or agent client came to
 * exist in Hydra — mediated DCR (`POST /api/hydra/register`) or CIMD document
 * resolution (`GET /api/hydra/authorize`).
 *
 * This is the one audit surface that is **not account-scoped**: both
 * onboarding paths run before any account is identified, so the server gates
 * it on the admin role instead of an account filter and a non-admin gets 403.
 *
 * It is a log, not a registry — current client state lives in Hydra. Rows are
 * a snapshot taken at write time, so a `refreshed` row sits alongside the
 * original `registered` one rather than replacing it, and a `rejected` row
 * describes a client that never existed at all.
 */
import { apiFetch } from "../api.js";

export type OAuthClientOrigin = "dcr" | "cimd";

export interface OAuthClientRegistration {
  id: string;
  /** Hydra's `client_id`: a UUID for DCR, the Client Identifier URL for CIMD. */
  clientId: string;
  origin: OAuthClientOrigin;
  /**
   * `registered` | `refreshed` | `rejected`, and more over time (#255 adds
   * `blocked`) — treat it as an open string, not a union.
   */
  event: string;
  clientName: string | null;
  /** The CIMD `client_id` hostname; null for DCR, which has no document. */
  metadataHost: string | null;
  authMethod: string | null;
  redirectUris: string[];
  scope: string | null;
  /** Rejection cause, or what changed on a refresh. */
  reason: string | null;
  sourceIp: string | null;
  createdAt: string;
}

export interface OAuthClientPage {
  rows: OAuthClientRegistration[];
  nextCursor: string | null;
}

export interface OAuthClientFilters {
  clientId?: string;
  origin?: string;
  event?: string;
}

/** Thrown when the caller does not hold the admin role (HTTP 403). */
export class NotAdminError extends Error {
  constructor() {
    super("Admin role required");
    this.name = "NotAdminError";
  }
}

export async function fetchOAuthClients(
  filters: OAuthClientFilters = {},
  cursor?: string,
  limit = 50,
): Promise<OAuthClientPage> {
  const params = new URLSearchParams();
  if (filters.clientId) params.set("clientId", filters.clientId);
  if (filters.origin) params.set("origin", filters.origin);
  if (filters.event) params.set("event", filters.event);
  if (cursor) params.set("cursor", cursor);
  params.set("limit", String(limit));
  const res = await apiFetch(`/api/audit/oauth-clients?${params}`);
  if (res.status === 403) throw new NotAdminError();
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || "Failed to fetch the OAuth client log");
  }
  return res.json();
}

/**
 * How a client identifies itself in the list. For CIMD the hostname is the
 * identity cue the spec wants surfaced
 * (draft-ietf-oauth-client-id-metadata-document-02 §9.1) — it is the only part
 * of a URL `client_id` an attacker cannot choose freely.
 */
export function displayIdentity(row: OAuthClientRegistration): string {
  if (row.origin === "cimd" && row.metadataHost) return row.metadataHost;
  return row.clientName || row.clientId || "unknown client";
}
