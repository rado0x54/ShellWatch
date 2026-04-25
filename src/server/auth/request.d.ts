import "fastify";

declare module "fastify" {
  interface FastifyRequest {
    /**
     * Owning account ID. Set by the auth gate (cookie session) or API-key auth
     * before the route handler runs. The auth gate 401s any /api/* or /ws
     * request that reaches a handler without one, so handlers can rely on this
     * being a real string. Exempt routes (e.g. /health, /login, /api/auth/*)
     * never read it; the decoration default is an unsafe-cast sentinel.
     */
    accountId: string;
  }
}
