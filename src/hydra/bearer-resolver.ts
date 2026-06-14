// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Resolves an opaque bearer access token to a ShellWatch principal via RFC 7662
 * introspection against Hydra (#217), with a short cache.
 *
 * Every token reaching ShellWatch is an `authorization_code` token whose `sub`
 * IS the ShellWatch account id — the human who logged in (web UI, MCP client,
 * or agent-client all use the same DCR + authcode + PKCE flow). The OAuth
 * client is never bound to an account, so there's nothing to map: `sub` is the
 * account, and the granted `scope` distinguishes the surface (ui/mcp/agent).
 *
 * Results are cached for hydra.introspectionCacheTtlMs (default 60s) to amortize
 * bursts; that window also bounds how long a revoked token keeps working.
 * Failures introspecting fail CLOSED (return null → 401).
 */
import type { HydraAdminClient } from "./admin-client.js";

/** What the bearer gate sets on `request.apiKey` (audit fields keep the api-key name; see request.d.ts). */
export interface BearerPrincipal {
  accountId: string;
  /** Human label for audit: derived from the OAuth client id that minted the token. */
  label: string;
  /** Short, non-secret client identifier for audit (client id prefix). */
  keyPrefix: string;
  /** Granted scopes from the introspected token. */
  scopes: string[];
}

export type BearerResolver = (token: string) => Promise<BearerPrincipal | null>;

interface CacheEntry {
  value: BearerPrincipal | null;
  expiresAt: number;
}

export interface CreateBearerResolverParams {
  admin: HydraAdminClient;
  cacheTtlMs: number;
  /** Injectable clock for tests. Defaults to Date.now. */
  now?: () => number;
}

const MAX_CACHE_ENTRIES = 2048;

function shortId(id: string | undefined): string {
  if (!id) return "unknown";
  return id.length <= 12 ? id : id.slice(0, 12);
}

export function createBearerResolver(params: CreateBearerResolverParams): BearerResolver {
  const { admin, cacheTtlMs } = params;
  const now = params.now ?? Date.now;
  const cache = new Map<string, CacheEntry>();

  return async (token: string): Promise<BearerPrincipal | null> => {
    const cached = cache.get(token);
    const t = now();
    if (cached && cached.expiresAt > t) return cached.value;
    if (cached) cache.delete(token);

    let value: BearerPrincipal | null = null;
    try {
      const ins = await admin.introspect(token);
      // Default-deny: only access tokens authorize a request. Hydra tags every
      // introspected token with token_use, so requiring "access_token" is what
      // stops a refresh token (leaked from localStorage — it introspects active
      // with the same sub+scope) being replayed directly as a bearer.
      if (ins.active && ins.sub && ins.token_use === "access_token") {
        value = {
          accountId: ins.sub,
          label: ins.client_id ? `OAuth client ${shortId(ins.client_id)}` : "OAuth client",
          keyPrefix: shortId(ins.client_id),
          scopes: (ins.scope ?? "").split(/\s+/).filter(Boolean),
        };
      }
    } catch {
      // Fail closed: an unreachable / erroring introspection endpoint must not
      // grant access. Do not cache transient failures.
      return null;
    }

    if (cacheTtlMs > 0) {
      if (cache.size >= MAX_CACHE_ENTRIES) cache.clear();
      cache.set(token, { value, expiresAt: t + cacheTtlMs });
    }
    return value;
  };
}
