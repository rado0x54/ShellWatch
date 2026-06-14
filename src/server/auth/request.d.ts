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
     * exempt routes. The legacy field name `apiKey` is retained (rather than
     * renamed to e.g. `bearer`) to avoid churn across the request-handling
     * plumbing; it now holds a Hydra-introspected OAuth principal, not an API
     * key.
     */
    apiKey: BearerPrincipal | null;
  }
}
