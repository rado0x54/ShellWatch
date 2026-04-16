import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { UiSessionService } from "../../oauth/ui-session.js";
import type { AccountRepository } from "../../db/repositories/account-repo.js";
import { extractOAuthBearer } from "./extract-credentials.js";
import type { Principal, TokenVerifier } from "./token-verifier.js";

export interface AuthGateParams {
  app: FastifyInstance;
  accountRepo: AccountRepository;
  /** Resolves an opaque access token (from cookie or Authorization) to a {@link Principal}. */
  oauthVerifier: TokenVerifier;
  /** Owns session-cookie issuance and revocation; wires `/api/auth/logout`. */
  uiSession: UiSessionService;
  /** Returns true once at least one passkey exists — flips the gate from onboarding to enforce. */
  checkHasPasskeys: () => boolean;
}

/**
 * Gate for the Web UI and its REST / WS surface.
 *
 * The HMAC-signed `sw_session` cookie of the pre-OAuth world is gone.
 * Authenticated UI traffic now carries an opaque OAuth access token (in
 * the same cookie, now minted by the OAuth module), which the
 * `oauthVerifier` resolves to a {@link Principal}. API keys don't apply
 * here — the `/mcp` chain in `./register-auth-chain.ts` covers the
 * programmatic path.
 *
 * Onboarding behaviour is preserved: until the first passkey is
 * registered, the gate is fully open so the admin can bootstrap. Once
 * `checkHasPasskeys()` flips true, requests to protected routes without
 * a valid session are redirected to `/login` (or 401 for API calls).
 */
export function registerAuthGate({
  app,
  accountRepo,
  oauthVerifier,
  uiSession,
  checkHasPasskeys,
}: AuthGateParams): void {
  // Logout — destroys the session's grant (all tokens under it) and
  // clears the cookies. A subsequent request with the stolen cookie
  // value fails the oauthVerifier because the access token is gone
  // from storage.
  app.post("/api/auth/logout", async (request, reply) => {
    await uiSession.onLogout(request, reply);
    reply.send({ status: "logged_out" });
  });

  const alwaysExempt = new Set([
    "/health",
    "/api/auth/logout",
    "/api/auth/register",
    "/api/webauthn/login/options",
    "/api/webauthn/login/verify",
    "/api/webauthn/register/options",
    // Admin bootstrap: the first-passkey registration must work before
    // any passkey exists. The unauthenticated path is only reachable
    // while `hasPasskeys()` is false (see below); once the first
    // passkey is registered, this route becomes inaccessible to
    // unauthenticated callers via the normal principal check.
    "/api/webauthn/register/verify",
    "/login",
    "/register",
    "/mcp",
    "/agent-proxy",
    "/config.js",
  ]);

  // Cache passkey count to avoid a DB hit on every request.
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

  // This hook runs for *every* request regardless of whether earlier
  // hooks called `reply.hijack()` — Fastify does not short-circuit
  // onRequest on hijack. The OAuth mount hook hijacks `/oidc/*` traffic
  // but this gate still fires on those paths; the startsWith exemption
  // below is what keeps us from racing panva's response. Any future
  // work added here must stay safe to re-run against an already-sent
  // reply (no `reply.send()`, no double-write to `reply.raw`).
  app.addHook("onRequest", async (request, reply) => {
    const url = (request.url ?? "").split("?")[0] ?? "";

    // Static assets built by SvelteKit: /_app/* and friends.
    if (url.startsWith("/_app/")) return;
    // OAuth / MCP / well-known — covered by other hooks and routes.
    // Boundary-correct match (no `startsWith("/oidc/")` foot-gun where
    // `/oidcevil/...` would slip through AND no missed bare `/oidc`).
    if (url === "/oidc" || url.startsWith("/oidc/")) return;
    if (url === "/.well-known" || url.startsWith("/.well-known/")) return;
    if (alwaysExempt.has(url)) return;

    // Onboarding mode: before the first passkey is registered there is
    // no one to authenticate as, so the gate lets everything through.
    // Flips off once a passkey exists — subject to the ~5s cache
    // above, which is acceptable because the first-passkey flow runs
    // a handful of requests apart, not hundreds per second.
    if (!hasPasskeys()) return;

    let principal = await resolveUiPrincipal(request, oauthVerifier);
    if (!principal) {
      // Access token missing or expired. Try the rolling-refresh path
      // before declaring the session dead: if `sw_refresh` is still
      // valid and unconsumed, uiSession.tryRefresh rotates both
      // cookies and hands us back the new access token, which we
      // re-verify through the same verifier.
      const refreshed = await uiSession.tryRefresh(request, reply);
      if (refreshed) {
        principal = await oauthVerifier.verify(refreshed.accessToken);
      }
    }

    if (principal) {
      request.principal = principal;
      if (principal.accountId) {
        request.accountId = principal.accountId;
        accountRepo.touchLastUsed(principal.accountId);
      }
      return;
    }

    replyUnauthenticated(reply, url);
  });
}

async function resolveUiPrincipal(
  request: FastifyRequest,
  verifier: TokenVerifier,
): Promise<Principal | null> {
  const bearer = extractOAuthBearer(request);
  if (!bearer) return null;
  return verifier.verify(bearer);
}

function replyUnauthenticated(reply: FastifyReply, url: string): void {
  // Keep the behaviour divide from the old gate: API / WS callers get
  // a 401 with a JSON body they can parse; browser navigation lands on
  // /login.
  const isApi = url.startsWith("/api/") || url === "/ws";
  if (isApi) {
    reply.status(401).send({ error: "Authentication required" });
  } else {
    reply.redirect("/login");
  }
}
