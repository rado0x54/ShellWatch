import type Provider from "oidc-provider";
import { FIRST_PARTY_CLIENT_ID } from "./provider.js";

/**
 * First-party token minting for the Web UI.
 *
 * The UI is a same-origin SPA: running a redirect-based code+PKCE flow
 * against our own OAuth endpoints would amount to five same-origin 302s
 * that accomplish nothing passkey login hasn't already accomplished
 * (the authenticated-user decision). So the UI bypasses the redirect
 * dance — after a successful passkey verify, the server constructs an
 * opaque AccessToken and RefreshToken directly via panva's public model
 * APIs, binds them to a fresh Grant, and returns them to the caller for
 * HttpOnly-cookie placement. Security properties match the code flow
 * (passkey is the authentication step either way); see
 * docs/oauth-mcp.md "Deliberate deviation from textbook OAuth".
 */

export interface MintFirstPartyTokenInput {
  /** `accounts.id` — who the token represents. */
  accountId: string;
  /**
   * Resource indicator bound into the token's `aud`. The verifier that
   * accepts this token on some protected path uses the same string as
   * its `expectedResource`.
   */
  audience: string;
  /** Scopes granted (e.g. `["mcp", "agent"]`). */
  scopes: string[];
}

export interface MintedFirstPartyTokens {
  accessToken: string;
  accessTokenExpiresAt: Date;
  refreshToken: string;
  refreshTokenExpiresAt: Date;
}

export interface FirstPartyTokenMinter {
  mint(input: MintFirstPartyTokenInput): Promise<MintedFirstPartyTokens>;
}

export interface FirstPartyTokenMinterOptions {
  /**
   * TTL for issued access tokens, in seconds. Drives
   * `resourceServer.accessTokenTTL` on the constructed AccessToken.
   *
   * Refresh-token TTL is deliberately absent: panva exposes no
   * per-token override on `RefreshToken`, so the only source of truth
   * for refresh TTL is the Provider-level `ttl.RefreshToken`. Reading
   * that via a separate channel here would invite drift; instead, the
   * returned `refreshTokenExpiresAt` is derived from what panva
   * actually persisted (see below).
   */
  accessTokenSeconds: number;
}

/**
 * `gty` value stamped onto every first-party token so audit / debugging
 * can tell them apart from tokens minted via the standard code flow.
 * Not spec-defined; panva is happy with any non-empty string.
 */
export const FIRST_PARTY_GRANT_TYPE = "first_party";

export function createFirstPartyTokenMinter(
  provider: Provider,
  options: FirstPartyTokenMinterOptions,
): FirstPartyTokenMinter {
  return {
    async mint({ accountId, audience, scopes }) {
      if (!accountId) {
        throw new Error("first-party: accountId is required");
      }
      if (!audience) {
        throw new Error("first-party: audience is required");
      }
      if (!scopes.length) {
        // A token with no scopes is indistinguishable from an
        // unauthorized token at the application layer, and future
        // scope-gated routes would silently lock out such tokens.
        // Reject at mint time rather than surface this confusion later.
        throw new Error("first-party: at least one scope is required");
      }

      const client = await provider.Client.find(FIRST_PARTY_CLIENT_ID);
      if (!client) {
        throw new Error(
          `first-party: client "${FIRST_PARTY_CLIENT_ID}" is not registered — Provider config is out of sync`,
        );
      }

      const scopeString = scopes.join(" ");

      // Persistent consent record. Panva's revokeByGrantId sweeps all
      // tokens under a grant, so logout can be implemented by destroying
      // this single grant if we ever need server-side invalidation.
      //
      // TODO: every successful login creates a fresh Grant row. Until we
      // wire a logout path (PR 5b or later) or a nightly reaper, the
      // table grows one row per (login, account). At ShellWatch scale
      // this takes years to become noticeable, but it is tracked and
      // should be cleaned up alongside the logout endpoint.
      const grant = new provider.Grant({
        clientId: FIRST_PARTY_CLIENT_ID,
        accountId,
      });
      grant.addResourceScope(audience, scopeString);
      const grantId = await grant.save();

      const accessToken = new provider.AccessToken({
        client,
        accountId,
        grantId,
        gty: FIRST_PARTY_GRANT_TYPE,
        aud: audience,
        scope: scopeString,
        // Force opaque format for this deployment even though the token
        // is minted outside the resourceIndicators code path that
        // normally carries the format decision.
        resourceServer: {
          scope: scopeString,
          audience,
          accessTokenTTL: options.accessTokenSeconds,
          accessTokenFormat: "opaque",
        },
      });
      const accessTokenValue = await accessToken.save();

      const refreshToken = new provider.RefreshToken({
        client,
        accountId,
        grantId,
        gty: FIRST_PARTY_GRANT_TYPE,
        scope: scopeString,
        resource: audience,
      });
      const refreshTokenValue = await refreshToken.save();

      // panva's `save()` writes `exp` into the stored payload but does
      // not mutate the in-memory instance. To return an expiry that
      // truly matches the server-side lifetime (otherwise cookie
      // Max-Age drifts from the actual token and we get silent 401s on
      // refresh), re-`find` each token and read `exp` off the
      // reconstructed record. Two extra reads per login — cheap, and
      // guarantees the returned shape can't lie about storage.
      const [savedAccess, savedRefresh] = await Promise.all([
        provider.AccessToken.find(accessTokenValue),
        provider.RefreshToken.find(refreshTokenValue),
      ]);
      if (!savedAccess?.exp || !savedRefresh?.exp) {
        throw new Error(
          "first-party: could not read exp from a just-saved token — unexpected provider state",
        );
      }

      return {
        accessToken: accessTokenValue,
        accessTokenExpiresAt: new Date(savedAccess.exp * 1000),
        refreshToken: refreshTokenValue,
        refreshTokenExpiresAt: new Date(savedRefresh.exp * 1000),
      };
    },
  };
}
