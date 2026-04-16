import type { FastifyBaseLogger, FastifyReply, FastifyRequest } from "fastify";
import type Provider from "oidc-provider";
import {
  ACCESS_COOKIE_NAME,
  REFRESH_COOKIE_NAME,
  clearFirstPartyCookies,
  setFirstPartyCookies,
} from "./cookie.js";
import type { FirstPartyTokenMinter, MintedFirstPartyTokens } from "./first-party.js";

/**
 * Seam between passkey code (OAuth-agnostic) and the OAuth module.
 *
 * Passkey login / self-register call {@link UiSessionService.onLoginSuccess}
 * after a successful WebAuthn verify; the implementation mints a
 * first-party token pair and writes them to HttpOnly cookies. Passkey
 * code does not import from `src/oauth` directly, so the minter /
 * provider are held here.
 *
 * {@link UiSessionService.onLogout} destroys the grant that backs the
 * current session (which sweeps every token under it via
 * `revokeByGrantId`) and clears the cookies. An attacker with a
 * previously stolen cookie loses access immediately.
 */
export interface UiSessionService {
  onLoginSuccess(
    request: FastifyRequest,
    reply: FastifyReply,
    input: { accountId: string },
  ): Promise<void>;

  onLogout(request: FastifyRequest, reply: FastifyReply): Promise<void>;

  /**
   * Rolling session refresh. Called when the access token has expired
   * or is near expiry. Reads the `sw_refresh` cookie, consumes it, and
   * mints a new token pair under the same Grant; returns the new
   * access token string on success or `null` when refresh is
   * unavailable (no cookie, expired, consumed, missing grant). On
   * success the response cookies are rotated.
   *
   * Auth-gate calls this only after `OAuthTokenVerifier.verify` on the
   * access cookie has returned null; callers do not need to
   * pre-validate.
   *
   * Single-call-per-request contract: reads cookies off
   * `request.headers.cookie`, which does not reflect cookies set on
   * the outgoing reply. Calling `tryRefresh` twice in the same request
   * would re-see the stale (now-consumed) refresh and return null.
   * Don't.
   */
  tryRefresh(request: FastifyRequest, reply: FastifyReply): Promise<{ accessToken: string } | null>;

  /** Exposed for tests that need to construct a session cookie. */
  readonly cookieNames: {
    access: typeof ACCESS_COOKIE_NAME;
    refresh: typeof REFRESH_COOKIE_NAME;
  };
}

export interface UiSessionServiceDeps {
  provider: Provider;
  minter: FirstPartyTokenMinter;
  /**
   * Resource URL bound into the UI's access-token `aud`. The OAuth
   * verifier that accepts this token on UI routes uses the same string
   * as its `expectedResource`.
   */
  audience: string;
  /** Scopes granted to the UI session. */
  scopes: string[];
}

export function createUiSessionService(deps: UiSessionServiceDeps): UiSessionService {
  // Coalesces parallel refreshes racing on the same refresh cookie.
  // On page load a browser often fires N requests at once; without
  // this map the first request consumes the refresh token, the rest
  // see `consumed` and get 401 — the user perceives a random partial
  // page failure. Map is per-service, closure-scoped; an entry is
  // cleared as soon as the underlying mint resolves so the next
  // rotation starts fresh.
  const inFlightRefreshes = new Map<string, Promise<MintedFirstPartyTokens | null>>();

  async function performRefresh(
    refreshValue: string,
    log: FastifyBaseLogger,
  ): Promise<MintedFirstPartyTokens | null> {
    const record = await deps.provider.RefreshToken.find(refreshValue);
    // `find` already filters expired records; `consumed` catches the
    // replay case where an attacker holding a stolen cookie tries to
    // spend the same refresh twice.
    if (!record) return null;
    if (record.isExpired) return null;

    if ((record as { consumed?: unknown }).consumed) {
      // Replayed refresh is a compromise signal. Tear down the entire
      // grant so the legitimate user's rotated tokens also stop working,
      // forcing a re-login — the standard OAuth 2.1 posture.
      if (record.grantId) {
        log.warn(
          { grantId: record.grantId, jti: record.jti },
          "first-party refresh replay detected — revoking grant",
        );
        await Promise.all([
          deps.provider.AccessToken.revokeByGrantId(record.grantId),
          deps.provider.RefreshToken.revokeByGrantId(record.grantId),
        ]);
      }
      return null;
    }

    if (!record.grantId || !record.accountId) return null;

    // Resource + scope come off the stored refresh token so rotation
    // preserves the original grant's shape. The first-party flow mints
    // with a single resource today — if this code is ever reused for a
    // multi-resource grant, narrowing to `[0]` here would silently drop
    // the rest. For now the assumption is explicit.
    const audience = Array.isArray(record.resource) ? record.resource[0] : record.resource;
    if (!audience) return null;
    const scopes = (record.scope ?? "").split(/\s+/).filter(Boolean);
    if (!scopes.length) return null;

    // Consume before minting so a crash between these two awaits
    // can't leave a reusable refresh token in the store.
    await record.consume();

    const tokens = await deps.minter.mintUnderGrant({
      accountId: record.accountId,
      grantId: record.grantId,
      audience,
      scopes,
    });

    log.info(
      { accountId: record.accountId, grantId: record.grantId },
      "first-party session refreshed",
    );
    return tokens;
  }

  return {
    cookieNames: { access: ACCESS_COOKIE_NAME, refresh: REFRESH_COOKIE_NAME },

    async onLoginSuccess(request, reply, { accountId }) {
      const tokens = await deps.minter.mint({
        accountId,
        audience: deps.audience,
        scopes: deps.scopes,
      });
      setFirstPartyCookies(request, reply, { tokens });
    },

    async tryRefresh(request, reply) {
      const refreshValue = readCookie(request.headers.cookie, REFRESH_COOKIE_NAME);
      if (!refreshValue) return null;

      let pending = inFlightRefreshes.get(refreshValue);
      if (!pending) {
        pending = performRefresh(refreshValue, request.log).finally(() => {
          inFlightRefreshes.delete(refreshValue);
        });
        inFlightRefreshes.set(refreshValue, pending);
      }

      const tokens = await pending;
      if (!tokens) return null;

      // Each concurrent caller still writes its own cookies on its
      // own reply — the mint itself was coalesced above, but every
      // pending HTTP response needs the rotated `Set-Cookie` headers.
      setFirstPartyCookies(request, reply, { tokens });
      return { accessToken: tokens.accessToken };
    },

    async onLogout(request, reply) {
      const accessValue = readCookie(request.headers.cookie, ACCESS_COOKIE_NAME);

      // Destroying the grant sweeps every token issued under it —
      // access, refresh, and any others panva stores with grantId set.
      // Works even if the access cookie is already gone because the
      // refresh cookie happens to still be present; we use whichever we
      // can find.
      const candidateJtis = [
        accessValue,
        readCookie(request.headers.cookie, REFRESH_COOKIE_NAME),
      ].filter((v): v is string => Boolean(v));

      for (const jti of candidateJtis) {
        const grantId = await grantIdFromToken(deps.provider, jti);
        if (grantId) {
          await Promise.all([
            deps.provider.AccessToken.revokeByGrantId(grantId),
            deps.provider.RefreshToken.revokeByGrantId(grantId),
          ]);
          break;
        }
      }

      clearFirstPartyCookies(request, reply);
    },
  };
}

async function grantIdFromToken(provider: Provider, opaque: string): Promise<string | null> {
  const access = await provider.AccessToken.find(opaque);
  if (access?.grantId) return access.grantId;
  const refresh = await provider.RefreshToken.find(opaque);
  if (refresh?.grantId) return refresh.grantId;
  return null;
}

function readCookie(cookieHeader: string | undefined, name: string): string | null {
  if (!cookieHeader) return null;
  const prefix = `${name}=`;
  for (const raw of cookieHeader.split(";")) {
    const trimmed = raw.trim();
    if (trimmed.startsWith(prefix)) return decodeURIComponent(trimmed.slice(prefix.length));
  }
  return null;
}
