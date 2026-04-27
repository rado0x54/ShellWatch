import "fastify";
import type { ApiKeyInfo } from "../../db/repositories/api-key-repo.js";

declare module "fastify" {
  interface FastifyRequest {
    /**
     * Owning account ID. Set by the auth gate (cookie session) or API-key auth
     * before the route handler runs. The auth gate 401s any /api/* or /ws
     * request that reaches a handler without one, so handlers can rely on this
     * being a real (non-empty) account id. Exempt routes (e.g. /health,
     * /login, /api/auth/*) never read it; the decoration default is "".
     */
    accountId: string;
    /**
     * Set by the bearer gate for /mcp and /agent-proxy. Null on routes
     * authenticated via session cookie (and on exempt routes).
     */
    apiKey: ApiKeyInfo | null;
  }
}
