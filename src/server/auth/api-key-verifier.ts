import type { AccountRepository, ApiKeyRepository } from "../../db/index.js";
import { hashApiKey } from "./api-key-auth.js";
import type { Principal, TokenVerifier } from "./token-verifier.js";

/**
 * Wraps the existing API-key repository in the {@link TokenVerifier}
 * contract. The verifier touches `accounts.last_used_at` on every
 * successful resolution (carried over from the old onRequest hook) so the
 * UI's "last activity" display stays accurate once OAuth-based auth routes
 * reach for this same path.
 *
 * The raw token must already have been extracted from the request via
 * {@link ./extract-credentials.extractApiKey}; this class does no header
 * parsing.
 */
export function createApiKeyVerifier(
  apiKeyRepo: ApiKeyRepository,
  accountRepo: AccountRepository,
): TokenVerifier {
  return {
    async verify(raw: string): Promise<Principal | null> {
      if (!raw) return null;
      const key = await apiKeyRepo.findByHash(hashApiKey(raw));
      if (!key || !key.enabled) return null;

      if (key.accountId) {
        accountRepo.touchLastUsed(key.accountId);
      }

      return {
        accountId: key.accountId ?? "",
        // Legacy keys issued before scope-gating may have an empty
        // `scopes` array. Any future route that gates on a specific
        // scope MUST either back-fill scopes on existing keys or treat
        // an empty list as "all MCP/agent scopes" (the pre-gating
        // default); silently locking out pre-existing keys on rollout
        // is not acceptable.
        scopes: key.scopes ?? [],
        source: "api-key",
        tokenId: key.id,
      };
    },
  };
}
