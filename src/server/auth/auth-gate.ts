import { count } from "drizzle-orm";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { AccountRepository } from "../../db/repositories/account-repo.js";
import type { ShellWatchDB } from "../../db/connection.js";
import { adminAccount, webauthnCredentials } from "../../db/schema.js";
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
  accountRepo?: AccountRepository,
): void {
  if (!db) return;
  const dbRef = db;

  let cachedCount: number | null = null;
  let cacheTime = 0;
  const CACHE_TTL_MS = 5000;

  function getPasskeyCount(): number {
    const now = Date.now();
    if (cachedCount !== null && now - cacheTime < CACHE_TTL_MS) return cachedCount;
    const result = dbRef.select({ count: count() }).from(webauthnCredentials).get();
    cachedCount = result?.count ?? 0;
    cacheTime = now;
    return cachedCount;
  }

  // Logout: clear session cookie
  app.post(`${basePath}/api/auth/logout`, async (request, reply) => {
    const secure = request.protocol === "https" || !!request.headers["x-forwarded-proto"];
    reply
      .header(
        "Set-Cookie",
        `${COOKIE_NAME}=; Path=${basePath || "/"}; Max-Age=0; HttpOnly; ${secure ? "Secure; " : ""}SameSite=Strict`,
      )
      .send({ status: "logged_out" });
  });

  // Exempt paths that don't require session auth
  const exemptSuffixes = [
    "/health",
    "/mcp",
    "/api/webauthn/login/options",
    "/api/webauthn/login/verify",
    "/api/webauthn/status",
    "/api/auth/logout",
    "/login",
    "/config.js",
  ];

  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    // Bootstrap mode: no passkeys = open access, but resolve admin account
    if (getPasskeyCount() === 0) {
      const admin = dbRef.select({ accountId: adminAccount.accountId }).from(adminAccount).get();
      if (admin) {
        request.accountId = admin.accountId;
      }
      return;
    }

    const url = request.url.split("?")[0];

    // Check exempt paths
    for (const suffix of exemptSuffixes) {
      if (url === `${basePath}${suffix}`) return;
    }

    // Allow static assets (SvelteKit serves from /_app/)
    if (url.startsWith(`${basePath}/_app/`)) return;

    // Verify session cookie
    const cookie = parseCookie(request.headers.cookie, COOKIE_NAME);
    if (cookie) {
      const session = verifySessionCookie(cookie, secret);
      if (session) {
        request.accountId = session.sub;
        if (accountRepo && session.sub) {
          accountRepo.touchLastUsed(session.sub);
        }
        return;
      }
    }

    // Not authenticated
    const isApiOrWs = url.startsWith(`${basePath}/api/`) || url === `${basePath}/ws`;

    if (isApiOrWs) {
      reply.status(401).send({ error: "Authentication required" });
    } else {
      reply.redirect(`${basePath}/login`);
    }
  });
}
