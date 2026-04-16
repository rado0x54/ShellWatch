import type { FastifyRequest } from "fastify";

/** Cookie name carrying the opaque OAuth access token for browser sessions. */
export const SESSION_COOKIE_NAME = "sw_session";

/**
 * Recognisable prefix for ShellWatch API keys. Used to discriminate an
 * `Authorization: Bearer sw_…` value from an opaque OAuth access token so
 * the API-key verifier can pick it up via the legacy header during the
 * migration window.
 */
const API_KEY_PREFIX = "sw_";

/**
 * Pulls an OAuth access token out of a request. Checks the `Authorization`
 * header first (programmatic clients) and then the `sw_session` HttpOnly
 * cookie (browser). Returns `null` when nothing matches.
 *
 * Deliberately ignores `Authorization: Bearer` values that start with the
 * ShellWatch API-key prefix — those are routed to the API-key verifier via
 * {@link extractApiKey} instead, so the same header won't accidentally be
 * fed to two different verifiers and a hash collision miss can't
 * cross-pollinate.
 */
export function extractOAuthBearer(req: FastifyRequest): string | null {
  const auth = req.headers.authorization;
  if (auth?.startsWith("Bearer ")) {
    const token = auth.slice("Bearer ".length);
    if (!token.startsWith(API_KEY_PREFIX)) return token;
  }

  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    const cookie = readCookie(cookieHeader, SESSION_COOKIE_NAME);
    if (cookie) return cookie;
  }

  return null;
}

/**
 * Pulls an API key out of a request. Preferred source is the `X-API-Key`
 * header. As a migration convenience during the OAuth rollout, also accepts
 * `Authorization: Bearer sw_…` — existing MCP clients configured against
 * the pre-OAuth API-key scheme continue to work unchanged. A follow-up PR
 * will drop the Authorization fallback.
 */
export function extractApiKey(req: FastifyRequest): string | null {
  const headerValue = req.headers["x-api-key"];
  if (typeof headerValue === "string" && headerValue.length > 0) {
    return headerValue;
  }
  if (Array.isArray(headerValue) && typeof headerValue[0] === "string") {
    return headerValue[0];
  }

  const auth = req.headers.authorization;
  if (auth?.startsWith("Bearer ")) {
    const token = auth.slice("Bearer ".length);
    if (token.startsWith(API_KEY_PREFIX)) return token;
  }

  return null;
}

/**
 * Minimal cookie-header parser. Avoids pulling in a cookie-parsing
 * dependency for a single lookup; the Web UI cookies (sw_session,
 * sw_refresh) are controlled by us so the parsing surface is tiny.
 */
function readCookie(cookieHeader: string, name: string): string | null {
  const prefix = `${name}=`;
  const parts = cookieHeader.split(";");
  for (const raw of parts) {
    const trimmed = raw.trim();
    if (trimmed.startsWith(prefix)) {
      return decodeURIComponent(trimmed.slice(prefix.length));
    }
  }
  return null;
}
