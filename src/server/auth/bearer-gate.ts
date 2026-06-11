// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { type Config, UI_SCOPE } from "../../config/index.js";
import type { AccountRepository } from "../../db/index.js";
import type { BearerResolver } from "../../hydra/bearer-resolver.js";

export type BearerScope = "mcp" | "agent";

export { UI_SCOPE };

/**
 * Sentinel WebSocket subprotocol the browser SPA offers alongside the access
 * token (`["shellwatch.bearer", <token>]`) since it can't set an Authorization
 * header on a WS handshake. The server selects this sentinel as the negotiated
 * subprotocol (never the token). Mirrored client-side in ws.ts / ws-client.ts.
 */
export const WS_BEARER_SUBPROTOCOL = "shellwatch.bearer";

/**
 * Bearer scopes that guard a protected resource with RFC 9728 discovery
 * (`/mcp`, `/agent-proxy`). The web UI uses a separate `ui` scope (below) that
 * isn't an externally-discoverable resource, so it's kept out of this list.
 * Sorted alphabetically so rendered scope lines + discovery docs agree.
 */
export const BEARER_SCOPES = ["agent", "mcp"] as const satisfies readonly BearerScope[];

/**
 * Single source of truth for the protected-resource paths each scope guards.
 * Mirrored by the per-resource RFC 9728 discovery docs (src/hydra/routes.ts).
 */
export const BEARER_PATHS: Record<BearerScope, string> = {
  mcp: "/mcp",
  agent: "/agent-proxy",
};

export const WELL_KNOWN_PROTECTED_RESOURCE = "/.well-known/oauth-protected-resource";
export const RESOURCE_METADATA_PATHS: Record<BearerScope, string> = Object.fromEntries(
  BEARER_SCOPES.map((s) => [s, `${WELL_KNOWN_PROTECTED_RESOURCE}${BEARER_PATHS[s]}`]),
) as Record<BearerScope, string>;

export interface RegisterBearerGateParams {
  app: FastifyInstance;
  /**
   * Resolves an opaque bearer token to a principal via Hydra introspection
   * (#217). Injected so tests can stub it without a live Hydra.
   */
  resolveBearer: BearerResolver;
  accountRepo: AccountRepository;
  config: Config;
  /** Whether /agent-proxy is mounted (gates the agent path + its discovery doc). */
  agentProxyEnabled: boolean;
}

// Exact paths that never require a token.
const EXEMPT_EXACT = new Set([
  "/health",
  "/api/version",
  "/config.js",
  "/manifest.json",
  // Anonymous onboarding / bootstrap (passkey registration has no token yet).
  "/api/auth/register",
  "/api/auth/register/options",
  "/api/auth/passkey-status",
  // Mediated DCR — reached by clients before they have a token.
  "/oauth/register",
]);

// Path prefixes that never require a token.
//   /api/hydra/        — the passkey login + consent providers (establish auth).
//   /api/passkey-invite/ + /passkey-invite/ — anonymous invite registration.
//   /.well-known/      — OAuth discovery.
//   /_app/             — SvelteKit static assets.
const EXEMPT_PREFIXES = [
  "/api/hydra/",
  "/api/passkey-invite/",
  "/passkey-invite/",
  "/.well-known/",
  "/_app/",
];

/**
 * The one auth gate (#217). Every authenticated surface presents a Hydra
 * opaque access token; the gate introspects it (`sub` → account, scope per
 * path) and 401s otherwise:
 *
 *   - `/mcp`          → scope `mcp`     (Authorization: Bearer)
 *   - `/agent-proxy`  → scope `agent`   (Authorization: Bearer)
 *   - `/api/*`        → scope `ui`      (Authorization: Bearer)
 *   - `/ws`           → scope `ui`      (token via `Sec-WebSocket-Protocol:
 *                                        shellwatch.bearer, <token>` — browsers
 *                                        can't set headers on a WS handshake)
 *
 * Everything else (SPA HTML routes, static assets, exempt endpoints) passes
 * through — the SPA gates itself client-side and runs the OAuth redirect when
 * it has no token. For `/mcp` + `/agent-proxy`, failures carry the RFC 6750
 * `WWW-Authenticate` + RFC 9728 `resource_metadata` hint so OAuth-aware clients
 * can discover the Hydra issuer.
 *
 * Protection is decided by path, NOT by file extension: a protected path is
 * always gated even if it ends in `.png` etc. (no asset carve-out for `/api/*`,
 * `/ws`, `/mcp`, `/agent-proxy`), so a handler never sees `accountId === ""`.
 * Real static assets live outside those prefixes and fall through naturally.
 */
export function registerBearerGate(params: RegisterBearerGateParams): void {
  const { app, resolveBearer, accountRepo, config, agentProxyEnabled } = params;

  // Read at request time — test helpers patch externalUrl after listen().
  const resourceMetadataUrl = (scope: BearerScope): string =>
    `${config.server.externalUrl.replace(/\/+$/, "")}${RESOURCE_METADATA_PATHS[scope]}`;

  function send401(
    reply: FastifyReply,
    required: BearerScope | typeof UI_SCOPE,
    message: string,
    kind: "missing" | "invalid" | "scope",
  ): void {
    const status = kind === "scope" ? 403 : 401;
    const parts = [`Bearer realm="shellwatch"`];
    // RFC 9728 discovery hint only for the externally-discoverable resources.
    if (required === "mcp" || required === "agent") {
      parts.push(`resource_metadata="${resourceMetadataUrl(required)}"`);
    }
    if (kind === "invalid") parts.push(`error="invalid_token"`);
    if (kind === "scope") parts.push(`error="insufficient_scope"`);
    reply.status(status).header("WWW-Authenticate", parts.join(", ")).send({ error: message });
  }

  function isExempt(path: string): boolean {
    if (EXEMPT_EXACT.has(path)) return true;
    if (EXEMPT_PREFIXES.some((p) => path.startsWith(p))) return true;
    return false;
  }

  /** Which scope (if any) guards this path. null → not a protected route. */
  function requiredScope(path: string): BearerScope | typeof UI_SCOPE | null {
    if (path === "/mcp" || path.startsWith("/mcp/")) return "mcp";
    if (agentProxyEnabled && (path === "/agent-proxy" || path.startsWith("/agent-proxy/")))
      return "agent";
    if (path === "/ws") return UI_SCOPE;
    if (path.startsWith("/api/")) return UI_SCOPE;
    return null;
  }

  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    const path = request.url.split("?")[0];
    if (isExempt(path)) return;

    const scope = requiredScope(path);
    if (!scope) return; // SPA HTML routes / static — pass through.

    // Authorization: Bearer for normal requests + non-browser WS clients
    // (Go agent, MCP). Browsers can't set headers on a WS handshake, so the
    // SPA carries the token in `Sec-WebSocket-Protocol: shellwatch.bearer, <token>`
    // (a request header — unlike a query param, it's not in default access logs).
    let token: string | undefined;
    const auth = request.headers.authorization;
    if (auth?.startsWith("Bearer ")) {
      token = auth.slice(7);
    } else {
      const proto = request.headers["sec-websocket-protocol"];
      if (typeof proto === "string") {
        const parts = proto.split(",").map((s) => s.trim());
        if (parts[0] === WS_BEARER_SUBPROTOCOL && parts[1]) token = parts[1];
      }
    }
    if (!token) {
      send401(reply, scope, "Access token required", "missing");
      return;
    }

    const principal = await resolveBearer(token);
    if (!principal) {
      send401(reply, scope, "Invalid or expired access token", "invalid");
      return;
    }
    if (!principal.scopes.includes(scope)) {
      send401(reply, scope, `Token lacks '${scope}' scope`, "scope");
      return;
    }

    request.accountId = principal.accountId;
    request.apiKey = principal;
    accountRepo.touchLastUsed(principal.accountId);
  });
}
