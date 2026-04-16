import type { FastifyReply, FastifyRequest } from "fastify";
import type Provider from "oidc-provider";
import {
  ACCESS_COOKIE_NAME,
  REFRESH_COOKIE_NAME,
  clearFirstPartyCookies,
  setFirstPartyCookies,
} from "./cookie.js";
import type { FirstPartyTokenMinter } from "./first-party.js";

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
