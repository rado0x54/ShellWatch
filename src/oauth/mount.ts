import { Readable } from "node:stream";
import type { IncomingMessage } from "node:http";
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
    if (suffix !== "" && !suffix.startsWith("/") && !suffix.startsWith("?")) {
      return false;
    }
    // Interaction routes (/oidc/interaction/:uid/*) are Fastify routes,
    // not panva Koa routes. If we let the mount hook hijack them, panva
    // sees `/interaction/:uid` and 404s because it has no handler for
    // that path — the interaction URL is ours, not panva's. Exclude
    // them so Fastify's normal routing picks them up.
    if (suffix.startsWith("/interaction/") || suffix === "/interaction") {
      return false;
    }
    return true;
  };

  const handler = provider.callback();

  // NB: every onRequest hook in the app runs for every request
  // regardless of hijack. After this hook calls `reply.hijack()`,
  // downstream `onRequest` hooks still fire — but on a reply that
  // panva is mid-writing. Any of those downstream hooks must be
  // reply-side-effect-safe (no `reply.send`, no double-write). The
  // mirror of this note lives in `src/server/auth/auth-gate.ts`.
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
      // Real MCP clients include "refresh_token" in DCR `grant_types`
      // per RFC 7591. Panva v9 rejects it (OAuth 2.1 strictness).
      // Panva's Koa middleware API can't run before its own bodyparser/
      // router (they're compiled into a single middleware at
      // construction). So we buffer + normalize the body here — before
      // handing the request to panva — for POST /reg only.
      const req = await maybeNormalizeDcrBody(request.raw, strippedUrl);

      handler(req, reply.raw);
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

/**
 * For `POST /reg` (DCR) only: buffer the body, strip `refresh_token`
 * from `grant_types`, and return a new `IncomingMessage`-like readable
 * with the normalised content. For all other requests returns the
 * original `request.raw` unchanged.
 *
 * Why this can't live in panva's Koa layer: panva compiles its bodyparser
 * + router into a single composed middleware at `new Provider()` time.
 * Any `provider.use(fn)` runs AFTER that composed block, i.e. after
 * the DCR handler has already validated and rejected. The only
 * interception point available to us is here — before calling
 * `provider.callback()`.
 */
async function maybeNormalizeDcrBody(
  raw: IncomingMessage,
  strippedUrl: string,
): Promise<IncomingMessage> {
  if (raw.method !== "POST" || strippedUrl.split("?")[0] !== "/reg") {
    return raw;
  }

  const chunks: Buffer[] = [];
  await new Promise<void>((resolve, reject) => {
    raw.on("data", (chunk: Buffer) => chunks.push(chunk));
    raw.on("end", resolve);
    raw.on("error", reject);
  });

  let bodyBuf = Buffer.concat(chunks);
  try {
    const body = JSON.parse(bodyBuf.toString("utf8"));
    if (Array.isArray(body.grant_types)) {
      body.grant_types = body.grant_types.filter((gt: string) => gt !== "refresh_token");
      bodyBuf = Buffer.from(JSON.stringify(body));
    }
  } catch {
    // Not JSON or malformed — let panva handle the error.
  }

  // Build a Readable that replays the (possibly modified) body and
  // carries all the properties panva's Koa context reads from the
  // Node IncomingMessage (headers, method, url, socket, etc.).
  const replay = Object.assign(Readable.from([bodyBuf]), {
    headers: { ...raw.headers, "content-length": String(bodyBuf.length) },
    method: raw.method,
    url: raw.url,
    httpVersion: raw.httpVersion,
    httpVersionMajor: raw.httpVersionMajor,
    httpVersionMinor: raw.httpVersionMinor,
    socket: raw.socket,
    connection: raw.socket,
    // Express-compat property set by mount.ts just above.
    originalUrl: (raw as IncomingMessage & { originalUrl?: string }).originalUrl,
  });

  return replay as unknown as IncomingMessage;
}
