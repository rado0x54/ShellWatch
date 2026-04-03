import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { AccountRepository } from "../../db/repositories/account-repo.js";
import { verifySessionCookie } from "./session-cookie.js";

const COOKIE_NAME = "sw_session";

export function parseCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match?.[1];
}

export interface AuthGateParams {
  app: FastifyInstance;
  basePath: string;
  secret: string;
  accountRepo: AccountRepository;
}

export function registerAuthGate({ app, basePath, secret, accountRepo }: AuthGateParams): void {
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

  // Paths that never require a session
  const exemptSuffixes = [
    "/health",
    "/api/auth/logout",
    "/api/webauthn/login/options",
    "/api/webauthn/login/verify",
    "/api/webauthn/register/options",
    "/api/webauthn/register/verify",
    "/login",
    "/onboarding",
    "/mcp",
    "/config.js",
  ];

  function isExempt(url: string): boolean {
    for (const suffix of exemptSuffixes) {
      if (url === `${basePath}${suffix}`) return true;
    }
    return false;
  }

  // Cache passkey count to avoid DB queries on every request
  let cachedHasPasskeys: boolean | null = null;
  let cacheTime = 0;
  const CACHE_TTL_MS = 5000;

  function hasPasskeys(): boolean {
    const now = Date.now();
    if (cachedHasPasskeys !== null && now - cacheTime < CACHE_TTL_MS) return cachedHasPasskeys;
    cachedHasPasskeys = accountRepo.hasPasskeys();
    cacheTime = now;
    return cachedHasPasskeys;
  }

  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    const url = request.url.split("?")[0];

    // Static assets
    if (url.startsWith(`${basePath}/_app/`)) return;

    // Only apply auth to routes under basePath
    if (basePath && !url.startsWith(`${basePath}/`) && url !== basePath) return;

    // Exempt paths (login, registration, health, etc.)
    if (isExempt(url)) return;

    // No passkeys registered — open access
    if (!hasPasskeys()) return;

    // System is ready — require session cookie
    const cookie = parseCookie(request.headers.cookie, COOKIE_NAME);
    if (cookie) {
      const session = verifySessionCookie(cookie, secret);
      if (session) {
        request.accountId = session.sub;
        if (session.sub) {
          accountRepo.touchLastUsed(session.sub);
        }
        return;
      }
    }

    // Not authenticated
    const isApi = url.startsWith(`${basePath}/api/`) || url === `${basePath}/ws`;
    if (isApi) {
      reply.status(401).send({ error: "Authentication required" });
    } else {
      reply.redirect(`${basePath}/login`);
    }
  });
}
