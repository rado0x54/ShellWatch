/**
 * Unified principal resolution shared by `/mcp`, `/agent-proxy`, and
 * (from PR 5) the Web UI.
 *
 * Two credential types flow into this chain: API keys and OAuth access
 * tokens. Each arrives on its own input (`X-API-Key` header for keys,
 * `Authorization: Bearer …` or `sw_session` cookie for OAuth) and is
 * verified by its own {@link TokenVerifier}. The chain is not a generic
 * "try on the same string" fallback — each verifier reads its own source
 * via {@link ./extract-credentials}.
 */

export type AuthSource = "api-key" | "oauth";

export interface Principal {
  /** References `accounts.id`. The authenticated identity. */
  accountId: string;
  /** Capabilities (e.g. `"mcp"`, `"agent"`). */
  scopes: string[];
  /** Which credential type resolved the principal. */
  source: AuthSource;
  /** OAuth only — the `client_id` the token was issued to. */
  clientId?: string;
  /** Opaque token jti (OAuth) or api_key id; useful for audit logs. */
  tokenId?: string;
  /** Expiry. Always set for OAuth tokens; may be absent for API keys. */
  expiresAt?: Date;
}

export interface TokenVerifier {
  verify(bearer: string): Promise<Principal | null>;
}
