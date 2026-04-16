import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { extractApiKey, extractOAuthBearer } from "./extract-credentials.js";
import type { Principal, TokenVerifier } from "./token-verifier.js";

export interface RegisterAuthChainParams {
  app: FastifyInstance;
  /** Path prefix the chain protects, e.g. `"/mcp"`. Matches via `startsWith`. */
  protectedPath: string;
  /** API-key verifier (always required — keeps headless clients working). */
  apiKeyVerifier: TokenVerifier;
  /**
   * OAuth token verifier. Optional: when `oauth.enabled` is false the
   * chain degrades to an API-key-only gate and skips the WWW-Authenticate
   * resource metadata pointer in the 401 response.
   */
  oauthVerifier?: TokenVerifier;
  /**
   * Absolute URL of the Protected Resource Metadata document (RFC 9728).
   * Surfaced in the `WWW-Authenticate` challenge when both verifiers miss.
   * Required when `oauthVerifier` is supplied; ignored otherwise.
   */
  resourceMetadataUrl?: string;
}

/**
 * Registers the unified `Principal` resolver on `protectedPath`.
 *
 * Runs as an `onRequest` hook — fires before body parsing, independent of
 * route registration order. On a successful credential match, the
 * resolved principal is attached to the request as `req.principal` and
 * the legacy `req.accountId` decorator is populated for downstream code
 * that hasn't been updated to use `principal` yet.
 */
export function registerAuthChain(params: RegisterAuthChainParams): void {
  const { app, protectedPath, apiKeyVerifier, oauthVerifier, resourceMetadataUrl } = params;

  app.addHook("onRequest", async (request, reply) => {
    if (!matchesProtectedPath(request.url, protectedPath)) return;

    const principal = await resolvePrincipal(request, apiKeyVerifier, oauthVerifier);
    if (principal) {
      request.principal = principal;
      if (principal.accountId) request.accountId = principal.accountId;
      return;
    }

    sendAuthChallenge(reply, resourceMetadataUrl);
  });
}

/**
 * True when `url` is exactly `prefix` or a real sub-path / query under it.
 * Guards against the `startsWith` footgun where `/mcp` would otherwise
 * also match a sibling like `/mcpevil/...` — a legitimate future route
 * at `/mcp-admin` must not silently inherit the auth chain.
 */
function matchesProtectedPath(url: string, prefix: string): boolean {
  if (!url.startsWith(prefix)) return false;
  const suffix = url.slice(prefix.length);
  return suffix === "" || suffix.startsWith("/") || suffix.startsWith("?");
}

async function resolvePrincipal(
  request: FastifyRequest,
  apiKeyVerifier: TokenVerifier,
  oauthVerifier: TokenVerifier | undefined,
): Promise<Principal | null> {
  const apiKey = extractApiKey(request);
  if (apiKey) {
    const principal = await apiKeyVerifier.verify(apiKey);
    if (principal) return principal;
  }

  if (oauthVerifier) {
    const bearer = extractOAuthBearer(request);
    if (bearer) {
      const principal = await oauthVerifier.verify(bearer);
      if (principal) return principal;
    }
  }

  return null;
}

function sendAuthChallenge(reply: FastifyReply, resourceMetadataUrl: string | undefined): void {
  // RFC 6750 §3 + RFC 9728 §5. When OAuth is enabled we advertise the
  // Protected Resource Metadata URL so an MCP client can discover the
  // authorization server; without it we fall back to the legacy API-key
  // challenge string so existing error messages remain stable.
  if (resourceMetadataUrl) {
    reply.header(
      "WWW-Authenticate",
      `Bearer realm="shellwatch", resource_metadata="${resourceMetadataUrl}"`,
    );
    reply.status(401).send({ error: "authentication required" });
    return;
  }
  reply.status(401).send({ error: "API key required. Use Authorization: Bearer sw_..." });
}

// Fastify request decorators (see app.ts — `principal` is added here).
declare module "fastify" {
  interface FastifyRequest {
    principal?: Principal | null;
  }
}
