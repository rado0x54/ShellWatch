import type { FastifyReply, FastifyRequest } from "fastify";
import type { MintedFirstPartyTokens } from "./first-party.js";

/**
 * Name of the cookie carrying the opaque OAuth access token for browser
 * sessions. Mirrors the extractor in
 * `src/server/auth/extract-credentials.ts` — both live under this name so
 * the chain finds what the minter wrote.
 */
export const ACCESS_COOKIE_NAME = "sw_session";

/**
 * Name of the cookie carrying the long-lived opaque refresh token. Sent
 * on every request (see docs/oauth-mcp.md "Rolling session refresh") so
 * the server-side preHandler can rotate access tokens without the
 * browser getting involved.
 */
export const REFRESH_COOKIE_NAME = "sw_refresh";

export interface SetFirstPartyCookiesOptions {
  tokens: MintedFirstPartyTokens;
}

/**
 * Writes both `sw_session` (access) and `sw_refresh` (refresh) cookies
 * as HttpOnly, SameSite=Strict, Path=/, with `Secure` emitted whenever
 * the request looks HTTPS (trustProxy-aware — see `isRequestSecure`).
 *
 * `SameSite=Strict` is a deliberate choice for this product:
 *   - ShellWatch is a same-origin admin tool; no legitimate flow relies
 *     on top-level cross-site navigation carrying the session.
 *   - Strict blocks the GET-CSRF variant that `Lax` permits, which is
 *     worth the lost "follow a link from docs and land already-logged-in"
 *     convenience that's not relevant to this product.
 *
 * The refresh cookie rides along with every request (Path=/) so the
 * rolling-refresh preHandler can rotate on any request that finds the
 * access token expired — see docs/oauth-mcp.md "Rolling session refresh".
 */
export function setFirstPartyCookies(
  request: FastifyRequest,
  reply: FastifyReply,
  { tokens }: SetFirstPartyCookiesOptions,
): void {
  const secure = isRequestSecure(request);
  const secureAttr = secure ? "Secure; " : "";

  const accessMaxAge = Math.max(
    0,
    Math.floor((tokens.accessTokenExpiresAt.getTime() - Date.now()) / 1000),
  );
  const refreshMaxAge = Math.max(
    0,
    Math.floor((tokens.refreshTokenExpiresAt.getTime() - Date.now()) / 1000),
  );

  // `Set-Cookie` is one of the few headers that can legitimately repeat,
  // so we append rather than replace.
  reply.header(
    "Set-Cookie",
    `${ACCESS_COOKIE_NAME}=${encodeURIComponent(tokens.accessToken)}; Path=/; Max-Age=${accessMaxAge}; HttpOnly; ${secureAttr}SameSite=Strict`,
  );
  reply.header(
    "Set-Cookie",
    `${REFRESH_COOKIE_NAME}=${encodeURIComponent(tokens.refreshToken)}; Path=/; Max-Age=${refreshMaxAge}; HttpOnly; ${secureAttr}SameSite=Strict`,
  );
}

/**
 * Clears both cookies — used on logout or when an expired refresh makes
 * the session unrecoverable. Sets `Max-Age=0` with matching flags so a
 * strict browser actually drops the cookie.
 */
export function clearFirstPartyCookies(request: FastifyRequest, reply: FastifyReply): void {
  const secure = isRequestSecure(request);
  const secureAttr = secure ? "Secure; " : "";

  reply.header(
    "Set-Cookie",
    `${ACCESS_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; ${secureAttr}SameSite=Strict`,
  );
  reply.header(
    "Set-Cookie",
    `${REFRESH_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; ${secureAttr}SameSite=Strict`,
  );
}

function isRequestSecure(request: FastifyRequest): boolean {
  // `request.protocol` is already trustProxy-aware: Fastify honours
  // `X-Forwarded-Proto` only when the TCP peer is inside the configured
  // `server.trustProxy` set. Reading the header directly would bypass
  // that invariant and let any client flip the Secure flag on a plain
  // HTTP deployment — self-DoS, not a compromise, but wrong.
  return request.protocol === "https";
}
