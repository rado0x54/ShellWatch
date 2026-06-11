// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import "fastify";
import type { BearerPrincipal } from "../../hydra/bearer-resolver.js";

declare module "fastify" {
  interface FastifyRequest {
    /**
     * Owning account ID. Set by the bearer gate (from the introspected OAuth
     * token's `sub`) before the route handler runs. The gate 401s any
     * /api/* or /ws request that reaches a handler without one, so handlers can
     * rely on this being a real (non-empty) account id. Exempt routes (e.g.
     * /health, /login, /api/auth/*) never read it; default is "".
     */
    accountId: string;
    /**
     * The introspected OAuth principal set by the bearer gate (#217). Null on
     * exempt routes. The field name is retained (rather than renamed to e.g.
     * `bearer`) so the audit pipeline's apiKeyLabel/apiKeyPrefix plumbing keeps
     * working unchanged; those columns now carry the OAuth client label/id
     * rather than an API-key label.
     */
    apiKey: BearerPrincipal | null;
  }
}
