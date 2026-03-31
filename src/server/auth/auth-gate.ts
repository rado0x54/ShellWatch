import { count } from "drizzle-orm";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { ShellWatchDB } from "../../db/connection.js";
import { webauthnCredentials } from "../../db/schema.js";
import { verifySessionCookie } from "./session-cookie.js";

const COOKIE_NAME = "sw_session";

export function parseCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match?.[1];
}

export function registerAuthGate(
  app: FastifyInstance,
  db: ShellWatchDB | null,
  basePath: string,
  secret: string,
): void {
  if (!db) return;
  const dbRef = db;

  let cachedCount: number | null = null;
  let cacheTime = 0;
  const CACHE_TTL_MS = 5000;

  function getPasskeyCount(): number {
    const now = Date.now();
    if (cachedCount !== null && now - cacheTime < CACHE_TTL_MS) return cachedCount;
    const result = dbRef
      .select({ count: count() })
      .from(webauthnCredentials)
      .get();
    cachedCount = result?.count ?? 0;
    cacheTime = now;
    return cachedCount;
  }

  // Exempt paths that don't require session auth
  const exemptSuffixes = [
    "/health",
    "/mcp",
    "/api/webauthn/login/options",
    "/api/webauthn/login/verify",
    "/api/webauthn/status",
    "/login",
    "/config.js",
  ];

  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    // Bootstrap mode: no passkeys = open access
    if (getPasskeyCount() === 0) return;

    const url = request.url.split("?")[0];

    // Check exempt paths
    for (const suffix of exemptSuffixes) {
      if (url === `${basePath}${suffix}`) return;
    }

    // Allow static assets on the login page
    if (url.startsWith(`${basePath}/assets/`)) return;

    // Verify session cookie
    const cookie = parseCookie(request.headers.cookie, COOKIE_NAME);
    if (cookie) {
      const session = verifySessionCookie(cookie, secret);
      if (session) return;
    }

    // Not authenticated
    const isApiOrWs =
      url.startsWith(`${basePath}/api/`) ||
      url === `${basePath}/ws`;

    if (isApiOrWs) {
      reply.status(401).send({ error: "Authentication required" });
    } else {
      reply.redirect(`${basePath}/login`);
    }
  });
}
