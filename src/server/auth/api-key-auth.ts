import { createHash } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Config } from "../../config/index.js";
import type { AccountRepository, ApiKeyRepository } from "../../db/index.js";

export function hashApiKey(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

export interface RegisterApiKeyAuthParams {
  app: FastifyInstance;
  apiKeyRepo: ApiKeyRepository;
  accountRepo: AccountRepository;
  mcpPath: string;
  /** Source of truth for the public base URL used in WWW-Authenticate hints. */
  config: Config;
}

export function registerApiKeyAuth({
  app,
  apiKeyRepo,
  accountRepo,
  mcpPath,
  config,
}: RegisterApiKeyAuthParams): void {
  // Read at each request — test helpers mutate `config.server.externalUrl`
  // after `app.listen()` so the resource-metadata pointer matches the random
  // test port. Don't capture at register time.
  const resourceMetadataUrl = (): string =>
    `${config.server.externalUrl.replace(/\/+$/, "")}/.well-known/oauth-protected-resource`;

  /**
   * Per RFC 6750 §3:
   *  - `missing`: no Authorization header at all → omit the `error` param.
   *    Clients use this as "no token yet, start OAuth discovery".
   *  - `invalid`: a token was provided but it's bad → `error="invalid_token"`.
   *    Clients use this as "token rejected, redo the flow".
   */
  const sendUnauthorized = (
    reply: FastifyReply,
    message: string,
    kind: "missing" | "invalid",
  ): void => {
    const parts = [`Bearer realm="mcp"`, `resource_metadata="${resourceMetadataUrl()}"`];
    if (kind === "invalid") parts.push(`error="invalid_token"`);
    reply.status(401).header("WWW-Authenticate", parts.join(", ")).send({ error: message });
  };

  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.url.startsWith(mcpPath)) return;

    const auth = request.headers.authorization;
    if (!auth?.startsWith("Bearer ")) {
      sendUnauthorized(reply, "API key required. Use Authorization: Bearer sw_...", "missing");
      return;
    }

    const token = auth.slice(7);
    const hash = hashApiKey(token);
    const key = await apiKeyRepo.findByHash(hash);

    if (!key) {
      sendUnauthorized(reply, "Invalid API key", "invalid");
      return;
    }

    // ApiKeyInfo.accountId is non-null (DB schema enforces it). Assign
    // unconditionally so downstream MCP code can treat request.accountId as
    // string instead of carrying the looseness through every layer.
    request.accountId = key.accountId;
    accountRepo.touchLastUsed(key.accountId);
  });
}
