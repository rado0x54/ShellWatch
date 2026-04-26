import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Config } from "../../config/index.js";
import type { AccountRepository } from "../../db/index.js";
// Deep import: ApiKeyAuthRepository is not part of the public DB barrel — it's
// reached for here because bearer auth needs the cross-tenant findByHash. See #136.
import type { ApiKeyAuthRepository } from "../../db/repositories/api-key-repo.js";
import type { ApiKeyInfo } from "../../db/repositories/api-key-repo.js";
import { hashApiKey } from "./api-key-auth.js";

export type BearerScope = "mcp" | "agent";

export interface BearerPathConfig {
  /** Required scope on the API key. Requests with a key lacking this scope get 403. */
  requiredScope: BearerScope;
  /**
   * Failure-response shape:
   * - `rfc6750`: WWW-Authenticate header with `Bearer realm` + `resource_metadata`
   *   (so MCP clients can discover OAuth metadata and start the flow).
   * - `plain`: bare 401/403 JSON body — used for /agent-proxy where the client is
   *   a non-browser agent that doesn't speak OAuth discovery.
   */
  failureFormat: "rfc6750" | "plain";
}

export interface RegisterBearerGateParams {
  app: FastifyInstance;
  apiKeyRepo: ApiKeyAuthRepository;
  accountRepo: AccountRepository;
  config: Config;
  /** Map of URL prefixes → required scope and failure format. */
  paths: Record<string, BearerPathConfig>;
}

/**
 * Single onRequest hook that authenticates bearer-token routes (/mcp,
 * /agent-proxy). Sets `request.accountId` and `request.apiKey` on success;
 * returns 401/403 with the configured failure format on failure. WS upgrades
 * are rejected pre-handshake (the client sees an HTTP 401 from the upgrade
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
  const resourceMetadataUrl = (): string =>
    `${config.server.externalUrl.replace(/\/+$/, "")}/.well-known/oauth-protected-resource`;

  function send401(
    reply: FastifyReply,
    format: BearerPathConfig["failureFormat"],
    message: string,
    kind: "missing" | "invalid" | "scope",
  ): void {
    const status = kind === "scope" ? 403 : 401;
    if (format === "rfc6750") {
      const parts = [`Bearer realm="mcp"`, `resource_metadata="${resourceMetadataUrl()}"`];
      if (kind === "invalid") parts.push(`error="invalid_token"`);
      if (kind === "scope") parts.push(`error="insufficient_scope"`);
      reply.status(status).header("WWW-Authenticate", parts.join(", ")).send({ error: message });
    } else {
      reply.status(status).send({ error: message });
    }
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
      send401(reply, cfg.failureFormat, "API key required", "missing");
      return;
    }

    const token = auth.slice(7);
    const key = await apiKeyRepo.findByHash(hashApiKey(token));
    if (!key) {
      send401(reply, cfg.failureFormat, "Invalid API key", "invalid");
      return;
    }

    if (!key.scopes.includes(cfg.requiredScope)) {
      send401(reply, cfg.failureFormat, `API key lacks '${cfg.requiredScope}' scope`, "scope");
      return;
    }

    request.accountId = key.accountId;
    request.apiKey = key;
    accountRepo.touchLastUsed(key.accountId);
  });
}

declare module "fastify" {
  interface FastifyRequest {
    /**
     * Set by the bearer gate for /mcp and /agent-proxy. Null on routes
     * authenticated via session cookie (and on exempt routes).
     */
    apiKey: ApiKeyInfo | null;
  }
}
