import type { FastifyInstance } from "fastify";
import type Provider from "oidc-provider";

export interface MountOAuthProviderOptions {
  /**
   * Path prefix under which panva's routes should respond, e.g. `/oidc`.
   * Must match the pathname of the issuer URL the Provider was constructed
   * with — panva's internal router expects them to align.
   */
  prefix: string;
}

/**
 * Mount a panva `Provider` inside a Fastify app.
 *
 * Panva is a Koa app; `provider.callback()` returns a plain Node
 * `(req, res)` handler. We intercept matching requests in Fastify's
 * `onRequest` hook — which fires *before* body parsing and before
 * routing — hijack the reply, and hand the raw request/response pair off
 * to panva. Panva writes the response itself and ends the stream.
 *
 * This is the canonical pattern for mixing Koa-based libraries into
 * Fastify: anything that exposes a `(req, res) => void` signature can be
 * mounted this way. The alternative (using `@fastify/middie`) would add a
 * dependency for no other benefit.
 */
export function mountOAuthProvider(
  app: FastifyInstance,
  provider: Provider,
  options: MountOAuthProviderOptions,
): void {
  const { prefix } = options;
  if (!prefix.startsWith("/") || prefix.endsWith("/")) {
    throw new Error(
      `mountOAuthProvider: prefix must start with '/' and not end with one, got "${prefix}"`,
    );
  }

  const matches = (url: string): boolean => {
    if (!url.startsWith(prefix)) return false;
    // Only match the prefix itself or paths directly under it; never match a
    // sibling path that happens to share the prefix as a substring
    // (e.g. prefix "/oidc" should not match "/oidcsomething/...").
    const suffix = url.slice(prefix.length);
    return suffix === "" || suffix.startsWith("/") || suffix.startsWith("?");
  };

  const handler = provider.callback();

  app.addHook("onRequest", async (request, reply) => {
    const originalUrl = request.raw.url ?? "";
    if (!matches(originalUrl)) return;

    // Panva expects to be mounted "Express-style": the incoming request's
    // `url` holds the path *relative to the mount point*, and `originalUrl`
    // holds the full path including the prefix. Panva reads both —
    // `url` drives its internal router, `originalUrl` is used by
    // `urlFor` to reconstruct the issuer prefix for metadata responses.
    const strippedUrl = originalUrl.slice(prefix.length) || "/";
    const rawWithExpress = request.raw as typeof request.raw & { originalUrl?: string };
    rawWithExpress.originalUrl = originalUrl;
    request.raw.url = strippedUrl;

    reply.hijack();
    try {
      handler(request.raw, reply.raw);
      await new Promise<void>((resolve, reject) => {
        reply.raw.once("finish", resolve);
        reply.raw.once("close", resolve);
        reply.raw.once("error", reject);
      });
    } finally {
      request.raw.url = originalUrl;
      delete rawWithExpress.originalUrl;
    }
  });
}
