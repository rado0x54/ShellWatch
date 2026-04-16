import type Provider from "oidc-provider";
import type { Principal, TokenVerifier } from "../server/auth/token-verifier.js";

/**
 * Resolves an opaque panva access token into a {@link Principal}.
 *
 * Validation happens in-process via `provider.AccessToken.find` — which
 * reads the same SQLite adapter panva itself uses. No HTTP introspection
 * hop.
 *
 * Per RFC 8707, the token's resource indicators must include the
 * caller-declared expected resource for *this* route (e.g.
 * `https://host/mcp` for `/mcp`). This closes the cross-resource
 * passthrough hole where a token minted for `/agent-proxy` could slip
 * onto `/mcp` or vice versa.
 */
export interface OAuthTokenVerifierOptions {
  /**
   * Returns the absolute resource URL that a valid token MUST claim
   * (via its `resource`/`aud`) for the current request. Callers pass a
   * fresh function per mount point so we don't burn the mapping into this
   * module.
   */
  expectedResource: () => string;
}

export function createOAuthTokenVerifier(
  provider: Provider,
  options: OAuthTokenVerifierOptions,
): TokenVerifier {
  return {
    async verify(rawToken: string): Promise<Principal | null> {
      if (!rawToken) return null;

      const record = await provider.AccessToken.find(rawToken);
      if (!record) return null;
      if (record.isExpired) return null;

      // RFC 8707 audience binding. panva stores the resource indicator(s)
      // on `aud`. Tokens with no audience are rejected outright —
      // something always issued for this deployment must carry the
      // resource URL it was minted for.
      const expected = options.expectedResource();
      const declared = record.aud;
      const declaredList = Array.isArray(declared) ? declared : declared ? [declared] : [];
      if (!declaredList.includes(expected)) return null;

      // Tokens without a bound account (e.g. hypothetical future
      // client_credentials flows) can't produce a meaningful Principal
      // for ShellWatch, which identifies access by `accounts.id`. Reject
      // rather than hand back a half-populated record — matches the
      // symmetry of the audience-missing rejection above and prevents
      // the `Principal.accountId: string` contract from silently lying.
      if (!record.accountId) return null;

      return {
        accountId: record.accountId,
        scopes: Array.from(record.scopes ?? []),
        source: "oauth",
        clientId: record.clientId,
        tokenId: record.jti,
        expiresAt: record.exp ? new Date(record.exp * 1000) : undefined,
      };
    },
  };
}
