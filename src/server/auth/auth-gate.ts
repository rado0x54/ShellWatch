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

  // Paths exempt from the session-cookie check. Some are genuinely public
  // (health, login/register HTML, static config), others (/mcp, /agent-proxy)
  // are auth-gated by the bearer-gate downstream. Naming this "exempt" only
  // makes sense relative to *cookie* auth — see registerBearerGate.
  const cookieAuthExempt = new Set([
    "/health",
    "/api/version",
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

    // Cookie-auth-exempt paths
    if (cookieAuthExempt.has(url)) return;

    // Discovery metadata is always public
    if (url.startsWith("/.well-known/")) return;

    // Require a valid session cookie. First-passkey/bootstrap onboarding
    // happens via /api/auth/register (in cookieAuthExempt) — no special-case here.
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
