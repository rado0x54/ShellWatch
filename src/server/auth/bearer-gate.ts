// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Config } from "../../config/index.js";
import type { AccountRepository } from "../../db/index.js";
// Deep import: ApiKeyAuthRepository is not part of the public DB barrel — it's
// reached for here because bearer auth needs the cross-tenant findByHash. See #136.
import type { ApiKeyAuthRepository } from "../../db/repositories/api-key-repo.js";
import { hashApiKey } from "./api-key-auth.js";

export type BearerScope = "mcp" | "agent";

/**
 * Single source of truth for the set of bearer scopes ShellWatch supports.
 * The OAuth shim validates pasted / minted keys against this list and exposes
 * it via `scopes_supported` in the discovery doc. Sorted alphabetically so
 * the rendered "Issued scopes" line and the discovery doc agree on order.
 * Adding a new scope requires updating this array, the `BearerScope` union,
 * and the `BEARER_PATHS` map below.
 */
export const BEARER_SCOPES = ["agent", "mcp"] as const satisfies readonly BearerScope[];

/**
 * Single source of truth for the protected-resource paths each scope guards.
 * Mirrored by:
 *   - `registerBearerGate`'s `paths` config in `src/server/app.ts` (which
 *     scope is required at each path),
 *   - the OAuth shim's `resolveScopes` (which path each `resource` indicator
 *     maps to), and
 *   - the per-resource discovery docs in `routes.ts`.
 */
export const BEARER_PATHS: Record<BearerScope, string> = {
  mcp: "/mcp",
  agent: "/agent-proxy",
};

/**
 * Per-scope RFC 9728 protected-resource metadata path (relative to externalUrl).
 * Per spec §3.1, the well-known URI appends the resource path to
 * `${WELL_KNOWN_PROTECTED_RESOURCE}`. Derived rather than hand-written so a
 * future rename of `BEARER_PATHS.agent` propagates here automatically. The
 * legacy unsuffixed `/.well-known/oauth-protected-resource` still exists as a
 * back-compat alias for `/mcp` (see `routes.ts`).
 */
export const WELL_KNOWN_PROTECTED_RESOURCE = "/.well-known/oauth-protected-resource";
export const RESOURCE_METADATA_PATHS: Record<BearerScope, string> = Object.fromEntries(
  BEARER_SCOPES.map((s) => [s, `${WELL_KNOWN_PROTECTED_RESOURCE}${BEARER_PATHS[s]}`]),
) as Record<BearerScope, string>;

export interface BearerPathConfig {
  /** Required scope on the API key. Requests with a key lacking this scope get 403. */
  requiredScope: BearerScope;
}

export interface RegisterBearerGateParams {
  app: FastifyInstance;
  apiKeyRepo: ApiKeyAuthRepository;
  accountRepo: AccountRepository;
  config: Config;
  /** Map of URL prefixes → required scope. */
  paths: Record<string, BearerPathConfig>;
}

/**
 * Single onRequest hook that authenticates bearer-token routes (/mcp,
 * /agent-proxy). Sets `request.accountId` and `request.apiKey` on success;
 * returns RFC 6750 401/403 with `WWW-Authenticate: Bearer ...` on failure,
 * pointing the client at the matching RFC 9728 protected-resource metadata
 * URL so OAuth-aware clients can discover the issuer. WS upgrades are
 * rejected pre-handshake (the client sees an HTTP 401 from the upgrade
 * request, not a WS close code).
 *
 * Companion to the cookie-session auth-gate. Together the two gates cover all
 * authenticated routes; nothing reaches a handler without one of them
 * populating `request.accountId`.
 */
export function registerBearerGate(params: RegisterBearerGateParams): void {
  const { app, apiKeyRepo, accountRepo, config, paths } = params;
  const pathEntries = Object.entries(paths);

  // Read at request time — test helpers patch externalUrl after listen().
  const resourceMetadataUrl = (scope: BearerScope): string =>
    `${config.server.externalUrl.replace(/\/+$/, "")}${RESOURCE_METADATA_PATHS[scope]}`;

  function send401(
    reply: FastifyReply,
    scope: BearerScope,
    message: string,
    kind: "missing" | "invalid" | "scope",
  ): void {
    const status = kind === "scope" ? 403 : 401;
    // RFC 6750 §3 leaves the realm value to the resource server; we use a
    // single generic identifier across both protected paths.
    const parts = [
      `Bearer realm="shellwatch"`,
      `resource_metadata="${resourceMetadataUrl(scope)}"`,
    ];
    if (kind === "invalid") parts.push(`error="invalid_token"`);
    if (kind === "scope") parts.push(`error="insufficient_scope"`);
    reply.status(status).header("WWW-Authenticate", parts.join(", ")).send({ error: message });
  }

  function matchPath(url: string): BearerPathConfig | undefined {
    const path = url.split("?")[0];
    for (const [prefix, cfg] of pathEntries) {
      if (path === prefix || path.startsWith(`${prefix}/`)) return cfg;
    }
    return undefined;
  }

  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    const cfg = matchPath(request.url);
    if (!cfg) return;

    const auth = request.headers.authorization;
    if (!auth?.startsWith("Bearer ")) {
      send401(reply, cfg.requiredScope, "API key required", "missing");
      return;
    }

    const token = auth.slice(7);
    const key = await apiKeyRepo.findByHash(hashApiKey(token));
    if (!key) {
      send401(reply, cfg.requiredScope, "Invalid API key", "invalid");
      return;
    }

    if (!key.scopes.includes(cfg.requiredScope)) {
      send401(reply, cfg.requiredScope, `API key lacks '${cfg.requiredScope}' scope`, "scope");
      return;
    }

    request.accountId = key.accountId;
    request.apiKey = key;
    accountRepo.touchLastUsed(key.accountId);
  });
}
