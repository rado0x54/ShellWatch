import type { FastifyInstance } from "fastify";

export interface RegisterProtectedResourceMetadataParams {
  app: FastifyInstance;
  /** External base URL with any trailing slash already stripped. */
  baseUrl: string;
  /** Scopes advertised on issued tokens (mirrors oauth.scopes config). */
  scopes: string[];
  /** The resource paths that this metadata document describes. */
  resources?: string[];
}

/**
 * RFC 9728 Protected Resource Metadata.
 *
 * Emits `GET /.well-known/oauth-protected-resource` advertising which
 * authorization server(s) clients should talk to, which scopes apply,
 * and how bearer tokens are presented. The endpoint is the second half
 * of the `WWW-Authenticate: Bearer resource_metadata=…` challenge the
 * auth chain emits on 401 — MCP clients follow the pointer here to
 * discover the AS.
 *
 * Only call this when OAuth is enabled; emitting the document without
 * an AS behind it is misleading.
 */
export function registerProtectedResourceMetadata(
  params: RegisterProtectedResourceMetadataParams,
): void {
  const { app, baseUrl, scopes } = params;
  const resources = params.resources ?? ["/mcp"];

  // Keep the primary `resource` field as the first configured resource
  // for back-compat with MCP clients that only read that field. Every
  // resource URL shows up verbatim in the `resources` extension so
  // multi-resource-aware clients can enumerate.
  const resourceUrls = resources.map((path) => `${baseUrl}${path}`);

  const body = {
    resource: resourceUrls[0],
    resources: resourceUrls,
    authorization_servers: [`${baseUrl}/oidc`],
    scopes_supported: scopes,
    bearer_methods_supported: ["header"],
  };

  app.get("/.well-known/oauth-protected-resource", async (_req, reply) => {
    reply.type("application/json");
    return body;
  });
}
