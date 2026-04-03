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

  // Paths accessible without any authentication
  const alwaysExempt = ["/health", "/api/init", "/api/auth/logout", "/config.js"];

  // Additional paths accessible during onboarding (system not yet ready)
  const onboardingExempt = [
    "/onboarding",
    "/api/webauthn/register/options",
    "/api/webauthn/register/verify",
    "/api/webauthn/status",
  ];

  // Paths accessible when system is ready but user is not logged in
  const loginExempt = [
    "/login",
    "/api/webauthn/login/options",
    "/api/webauthn/login/verify",
    "/api/webauthn/status",
    "/mcp",
  ];

  function isExempt(url: string, suffixes: string[]): boolean {
    for (const suffix of suffixes) {
      if (url === `${basePath}${suffix}`) return true;
    }
    return false;
  }

  // Cache init status to avoid DB queries on every request
  let cachedInitStatus: ReturnType<AccountRepository["getInitStatus"]> | null = null;
  let cacheTime = 0;
  const CACHE_TTL_MS = 5000;

  function getInitStatus() {
    const now = Date.now();
    if (cachedInitStatus !== null && now - cacheTime < CACHE_TTL_MS) return cachedInitStatus;
    cachedInitStatus = accountRepo.getInitStatus();
    cacheTime = now;
    return cachedInitStatus;
  }

  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    const url = request.url.split("?")[0];

    // Always-exempt paths
    if (isExempt(url, alwaysExempt)) return;

    // Static assets
    if (url.startsWith(`${basePath}/_app/`)) return;

    // Only apply auth to routes under basePath (root redirect etc. are not our concern)
    if (basePath && !url.startsWith(`${basePath}/`) && url !== basePath) return;

    const initStatus = getInitStatus();

    // --- Onboarding mode: system not yet ready ---
    if (initStatus.status !== "ready") {
      // Resolve admin account if it exists (for onboarding passkey registration)
      if (initStatus.status === "passkey_required") {
        request.accountId = initStatus.accountId;
      }

      // Allow onboarding + login pages
      if (isExempt(url, onboardingExempt) || isExempt(url, loginExempt)) return;

      // Block everything else — redirect to onboarding
      const isApi = url.startsWith(`${basePath}/api/`) || url === `${basePath}/ws`;
      if (isApi) {
        reply.status(503).send({ error: "System setup required", initStatus: initStatus.status });
      } else {
        reply.redirect(`${basePath}/onboarding`);
      }
      return;
    }

    // --- System is ready: normal auth flow ---

    // Login-related paths are exempt
    if (isExempt(url, loginExempt)) return;

    // Verify session cookie
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
