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
  secret: string;
  accountRepo: AccountRepository;
  checkHasPasskeys: () => boolean;
}

export function registerAuthGate({
  app,
  secret,
  accountRepo,
  checkHasPasskeys,
}: AuthGateParams): void {
  // Logout: clear session cookie
  app.post("/api/auth/logout", async (request, reply) => {
    const secure = request.protocol === "https" || !!request.headers["x-forwarded-proto"];
    reply
      .header(
        "Set-Cookie",
        `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; ${secure ? "Secure; " : ""}SameSite=Strict`,
      )
      .send({ status: "logged_out" });
  });

  // Paths that never require a session
  const alwaysExempt = new Set([
    "/health",
    "/api/auth/logout",
    "/api/auth/register",
    "/api/webauthn/login/options",
    "/api/webauthn/login/verify",
    "/api/webauthn/register/options",
    "/login",
    "/register",
    "/mcp",
    "/agent-proxy",
    "/config.js",
  ]);

  // Only exempt during onboarding (no passkeys registered yet — admin bootstrap)
  const onboardingOnly = new Set(["/api/webauthn/register/verify"]);

  // Cache passkey count to avoid DB queries on every request
  let cachedHasPasskeys: boolean | null = null;
  let cacheTime = 0;
  const CACHE_TTL_MS = 5000;

  function hasPasskeys(): boolean {
    const now = Date.now();
    if (cachedHasPasskeys !== null && now - cacheTime < CACHE_TTL_MS) return cachedHasPasskeys;
    cachedHasPasskeys = checkHasPasskeys();
    cacheTime = now;
    return cachedHasPasskeys;
  }

  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    const url = request.url.split("?")[0];

    // Static assets
    if (url.startsWith("/_app/")) return;

    // Always-exempt paths
    if (alwaysExempt.has(url)) return;

    // Onboarding-only paths (registration, /onboarding) — exempt only when no passkeys exist
    if (!hasPasskeys()) {
      if (onboardingOnly.has(url)) return;
      // No passkeys — allow all other routes too (bootstrap mode)
      return;
    }

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
    const isApi = url.startsWith("/api/") || url === "/ws";
    if (isApi) {
      reply.status(401).send({ error: "Authentication required" });
    } else {
      reply.redirect("/login");
    }
  });
}
