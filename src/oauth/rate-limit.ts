import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";

export interface RegisterDcrRateLimitOptions {
  /** Request budget per rolling minute per source IP. */
  perMinute: number;
}

/**
 * Per-IP rolling-minute rate limit on `POST /oidc/reg` — the anonymous
 * Dynamic Client Registration endpoint. Without a ceiling, an attacker
 * could mint unbounded client rows and slowly exhaust the `oauth_clients`
 * table. Panva does not implement this itself.
 *
 * Bucketing is in-memory: works for single-process ShellWatch, would
 * need Redis (or equivalent) for a multi-process deployment. At
 * ShellWatch scale (one admin, one process) the memory cost is
 * negligible — the bookkeeping map is pruned whenever a caller comes
 * back after the window.
 */
export function registerDcrRateLimit(
  app: FastifyInstance,
  options: RegisterDcrRateLimitOptions,
): void {
  const windowMs = 60_000;
  const buckets = new Map<string, { count: number; resetAt: number }>();

  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    if (request.raw.method !== "POST") return;
    const url = (request.raw.url ?? "").split("?")[0];
    if (url !== "/oidc/reg") return;

    const ip = request.ip;
    const now = Date.now();
    const bucket = buckets.get(ip);

    if (!bucket || bucket.resetAt <= now) {
      buckets.set(ip, { count: 1, resetAt: now + windowMs });
      return;
    }

    bucket.count += 1;
    if (bucket.count <= options.perMinute) return;

    // Over budget. `reply.send()` inside an `onRequest` hook causes
    // Fastify to short-circuit all subsequent hooks — including the
    // panva mount hook that would otherwise write to the same stream.
    // Using `reply.hijack()` + `reply.raw.end()` here would NOT
    // prevent panva's hook from running (Fastify does not abort the
    // hook chain on hijack), leading to ERR_STREAM_WRITE_AFTER_END.
    const retryAfter = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
    request.log.warn({ ip, count: bucket.count }, "DCR rate limit exceeded");
    reply
      .status(429)
      .header("Retry-After", String(retryAfter))
      .send({
        error: "too_many_requests",
        error_description: `Dynamic client registration limit exceeded (${options.perMinute}/min). Retry after ${retryAfter}s.`,
      });
  });
}
