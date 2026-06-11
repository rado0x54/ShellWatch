// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import "fastify";
import type { BearerPrincipal } from "../../hydra/bearer-resolver.js";

declare module "fastify" {
  interface FastifyRequest {
    /**
     * Owning account ID. Set by the BFF auth gate (web session) or the bearer
     * gate (OAuth access token) before the route handler runs. The auth gate
     * 401s any /api/* or /ws request that reaches a handler without one, so
     * handlers can rely on this being a real (non-empty) account id. Exempt
     * routes (e.g. /health, /login, /api/auth/*) never read it; default is "".
     */
    accountId: string;
    /**
     * Set by the bearer gate for /mcp and /agent-proxy — the introspected OAuth
     * principal (#217). Null on routes authenticated via the BFF web session
     * (and on exempt routes). The field name is retained (rather than renamed
     * to e.g. `bearer`) so the audit pipeline's apiKeyLabel/apiKeyPrefix
     * plumbing keeps working unchanged; those columns now carry OAuth client
     * label/id rather than an API-key label.
     */
    apiKey: BearerPrincipal | null;
  }
}
