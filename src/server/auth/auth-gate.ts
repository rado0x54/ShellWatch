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
}

export function registerAuthGate({ app, secret, accountRepo }: AuthGateParams): void {
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
    "/api/auth/register/options",
    "/api/auth/login/options",
    "/api/auth/login",
    "/login",
    "/register",
    "/mcp",
    "/agent-proxy",
    "/config.js",
    "/manifest.json",
    // OAuth endpoints reached by the MCP client directly (no human, no session):
    "/oauth/register",
    "/oauth/token",
  ]);

  // Public static asset extensions — icons, logos, fonts. Not used by any API route.
  const publicAssetExtensions = [".svg", ".png", ".ico", ".webp", ".woff", ".woff2"];

  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    const url = request.url.split("?")[0];

    // Static assets
    if (url.startsWith("/_app/")) return;
    if (publicAssetExtensions.some((ext) => url.endsWith(ext))) return;

    // Always-exempt paths
    if (alwaysExempt.has(url)) return;

    // Discovery metadata is always public
    if (url.startsWith("/.well-known/")) return;

    // Require a valid session cookie. First-passkey/bootstrap onboarding
    // happens via /api/auth/register (in alwaysExempt) — no special-case here.
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
      reply.redirect(`/login?redirect=${encodeURIComponent(request.url)}`);
    }
  });
}
