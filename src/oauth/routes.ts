/**
 * OAuth 2.1 DCR **shim** — just enough protocol to satisfy MCP clients
 * (Claude Desktop, MCP Inspector, etc.) and `shellwatch-agent` that don't
 * want to speak anything but OAuth. The access_token returned is either a
 * ShellWatch API key the user pasted, or one minted on the fly when the
 * user chooses "Create new key" on the authorize page. The minted key
 * carries whichever scope the client requested (`mcp` for MCP clients,
 * `agent` for the SSH agent thin client). This is NOT a real OAuth AS:
 *
 *   - DCR (`/oauth/register`) is ceremonial: any request is accepted and
 *     every client collapses onto a single shared `client_id`. There is
 *     no per-client registration state, no audit, no revocation endpoint.
 *   - The access_token is a first-class ShellWatch API key. Its lifetime
 *     equals the key's lifetime; revocation happens in Settings → API Keys.
 *   - No refresh tokens. API keys don't expire.
 *
 * Discovery/WWW-Authenticate URLs are derived from `config.server.externalUrl`
 * (read at each request, so test harnesses can mutate it after `listen()`).
 * Request headers are NEVER trusted for URL construction.
 */
import { randomBytes, randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyReply } from "fastify";
import type { Config } from "../config/index.js";
// Deep import: ApiKeyAuthRepository is not part of the public DB barrel — it's
// reached for here because the OAuth callback needs the cross-tenant findByHash. See #136.
import type { ApiKeyAuthRepository } from "../db/repositories/api-key-repo.js";
import { hashApiKey } from "../server/auth/api-key-auth.js";
import { BEARER_PATHS, BEARER_SCOPES, type BearerScope } from "../server/auth/bearer-gate.js";
import { createAuthCodeStore, type AuthCodeStore } from "./code-store.js";
import { verifyPkceS256 } from "./pkce.js";
import { renderAuthorizePage, type AuthorizeMode } from "./render.js";

export interface RegisterOAuthParams {
  app: FastifyInstance;
  /** Required — pasted keys are verified against this repo (must also carry `mcp` scope). */
  apiKeyRepo: ApiKeyAuthRepository;
  /**
   * Application config. `config.server.externalUrl` is used verbatim as the
   * base for all discovery metadata — never derived from request headers
   * (which a direct-exposed deployment cannot trust).
   */
  config: Config;
  /** Optional override for code TTL — primarily for tests. */
  codeTtlMs?: number;
}

export interface OAuthHandle {
  /** Stop the internal sweep timer and clear pending codes. */
  destroy(): void;
  /** Expose the code store for tests that need to seed / inspect. */
  _store: AuthCodeStore;
}

const STUB_CLIENT_ID = "sw-client";
const SAFE_REDIRECT_SCHEMES_BLOCKED = new Set(["javascript:", "data:", "file:"]);

const DEFAULT_SCOPE: BearerScope = "mcp";

export interface ResolvedScopes {
  /**
   * The scope set we will actually grant — always non-empty, always a subset
   * of BEARER_SCOPES, deduped and sorted. `[mcp]` is the fallback when no
   * recognized scope was requested.
   */
  issued: BearerScope[];
  /** Verbatim `scope` param (if any), preserved for display. */
  rawScope?: string;
  /** Verbatim `resource` param (if any), preserved for display. */
  rawResource?: string;
}

/**
 * Map the request's `scope` and `resource` parameters to the scope set we'll
 * issue. The shim is liberal: unknown scope tokens (`mcp:tools` style aliases,
 * outright bogus strings) and unknown `resource` URIs are silently dropped
 * rather than rejected — the user sees what they requested and what they
 * get on the authorize page, and can decide whether to proceed.
 */
function resolveScopes(
  rawScope: string | undefined,
  rawResource: string | undefined,
): ResolvedScopes {
  const issued = new Set<BearerScope>();

  if (rawScope) {
    for (const t of rawScope.split(/\s+/).filter(Boolean)) {
      if ((BEARER_SCOPES as readonly string[]).includes(t)) issued.add(t as BearerScope);
    }
  }

  if (rawResource) {
    try {
      const path = new URL(rawResource).pathname.replace(/\/+$/, "");
      if (path === BEARER_PATHS.mcp) issued.add("mcp");
      else if (path === BEARER_PATHS.agent) issued.add("agent");
    } catch {
      // unparseable URL — ignore, will be shown to the user verbatim
    }
  }

  if (issued.size === 0) issued.add(DEFAULT_SCOPE);
  return {
    issued: [...issued].sort() as BearerScope[],
    rawScope: rawScope || undefined,
    rawResource: rawResource || undefined,
  };
}

function isSafeRedirect(uri: string): boolean {
  try {
    const url = new URL(uri);
    return !SAFE_REDIRECT_SCHEMES_BLOCKED.has(url.protocol);
  } catch {
    return false;
  }
}

function asString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

export function registerOAuth({
  app,
  apiKeyRepo,
  config,
  codeTtlMs,
}: RegisterOAuthParams): OAuthHandle {
  const store = createAuthCodeStore({ ttlMs: codeTtlMs });
  // Read at each request — test helpers mutate `config.server.externalUrl`
  // after `app.listen()` to make discovery URLs match the random test port.
  // Don't capture at register time.
  const baseUrl = (): string => config.server.externalUrl.replace(/\/+$/, "");

  // Global form-body parser. Intentional: /oauth/authorize and /oauth/token
  // are the only form-encoded endpoints in the app, so registering app-wide
  // keeps the plugin self-contained. If another module ever needs its own
  // form parser, encapsulate this one behind `fastify.register()` first.
  app.addContentTypeParser(
    "application/x-www-form-urlencoded",
    { parseAs: "string" },
    (_req, body, done) => {
      try {
        const params = new URLSearchParams(body as string);
        const out: Record<string, string> = {};
        for (const [k, v] of params) out[k] = v;
        done(null, out);
      } catch (err) {
        done(err as Error, undefined);
      }
    },
  );

  app.get("/.well-known/oauth-protected-resource", async () => {
    const base = baseUrl();
    return {
      resource: `${base}${BEARER_PATHS.mcp}`,
      authorization_servers: [base],
      bearer_methods_supported: ["header"],
    };
  });

  app.get("/.well-known/oauth-authorization-server", async () => {
    const base = baseUrl();
    return {
      issuer: base,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      registration_endpoint: `${base}/oauth/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: [...BEARER_SCOPES],
    };
  });

  app.post("/oauth/register", async (req, reply) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const redirectUris = Array.isArray(body.redirect_uris)
      ? (body.redirect_uris as unknown[]).filter((u): u is string => typeof u === "string")
      : [];
    const clientName = asString(body.client_name) ?? "MCP Client";
    return reply.status(201).send({
      client_id: STUB_CLIENT_ID,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      redirect_uris: redirectUris,
      client_name: clientName,
    });
  });

  app.get("/oauth/authorize", async (req, reply) => {
    const q = (req.query ?? {}) as Record<string, string>;
    const responseType = q.response_type;
    const redirectUri = q.redirect_uri;
    const codeChallenge = q.code_challenge;
    const codeChallengeMethod = q.code_challenge_method;
    const clientId = q.client_id ?? STUB_CLIENT_ID;
    const state = q.state ?? "";

    if (responseType !== "code") {
      return reply.status(400).send({
        error: "unsupported_response_type",
        error_description: "response_type must be 'code'",
      });
    }
    if (!redirectUri || !isSafeRedirect(redirectUri)) {
      return reply.status(400).send({
        error: "invalid_request",
        error_description: "redirect_uri missing or uses a disallowed scheme",
      });
    }
    if (!codeChallenge) {
      return reply
        .status(400)
        .send({ error: "invalid_request", error_description: "code_challenge is required (PKCE)" });
    }
    if (codeChallengeMethod !== "S256") {
      return reply.status(400).send({
        error: "invalid_request",
        error_description: "code_challenge_method must be S256",
      });
    }

    const resolved = resolveScopes(q.scope, q.resource);
    const html = renderAuthorizePage({
      clientId,
      redirectUri,
      state,
      codeChallenge,
      codeChallengeMethod,
      resolved,
    });
    reply.type("text/html; charset=utf-8").send(html);
  });

  app.post("/oauth/authorize", async (req, reply) => {
    const b = (req.body ?? {}) as Record<string, string>;
    const redirectUri = b.redirect_uri;
    const state = b.state ?? "";
    const clientId = b.client_id || STUB_CLIENT_ID;
    const codeChallenge = b.code_challenge;
    const codeChallengeMethod = b.code_challenge_method;
    const mode: AuthorizeMode = b.mode === "existing" ? "existing" : "create";
    const newKeyLabel = (b.new_key_label ?? "").trim();
    if (
      !redirectUri ||
      !isSafeRedirect(redirectUri) ||
      !codeChallenge ||
      codeChallengeMethod !== "S256"
    ) {
      return reply
        .status(400)
        .send({ error: "invalid_request", error_description: "missing/invalid flow parameters" });
    }

    const resolved = resolveScopes(b.scope, b.resource);

    // 200 + error banner is the web-form convention. We still send the form
    // back so the user can correct their input without losing flow context.
    const rerender = (errorMessage: string): FastifyReply =>
      reply.status(200).type("text/html; charset=utf-8").send(
        renderAuthorizePage({
          clientId,
          redirectUri,
          state,
          codeChallenge,
          codeChallengeMethod,
          resolved,
          errorMessage,
          mode,
          newKeyLabel,
        }),
      );

    let pending:
      | { kind: "existing"; apiKey: string }
      | { kind: "create"; accountId: string; label: string; scopes: BearerScope[] };
    if (mode === "create") {
      if (!newKeyLabel) {
        return rerender("Please provide a name for the new API key.");
      }
      // /oauth/authorize is auth-gated upstream; req.accountId is set.
      // Deferred: we do NOT mint or persist the key here. If the client never
      // completes /oauth/token (user closes the tab, PKCE fails, code TTL
      // expires), no credential is created. See code-store.ts for the
      // discriminated entry type.
      pending = {
        kind: "create",
        accountId: req.accountId,
        label: newKeyLabel,
        scopes: resolved.issued,
      };
    } else {
      const pasted = b.api_key?.trim();
      if (!pasted) {
        return rerender("Enter an API key to continue.");
      }
      const key = await apiKeyRepo.findByHash(hashApiKey(pasted));
      if (!key) {
        return rerender("That API key is not recognized (or has been revoked).");
      }
      // Validate the pasted key has *at least* the requested scopes. Extra
      // scopes on the key are accepted, but they leak: the access token
      // returned at /oauth/token is the pasted key verbatim, so the client
      // ends up holding a key with broader rights than it requested. This is
      // inherent to shared bearer tokens — the only way to avoid it is to
      // mint a fresh narrow key (the "Create new key" flow). The page's
      // existing-mode help text discloses this so the user can choose
      // accordingly.
      const missing = resolved.issued.filter((s) => !key.scopes.includes(s));
      if (missing.length > 0) {
        const list = missing.map((s) => `'${s}'`).join(", ");
        return rerender(
          `This API key is missing required scope${missing.length === 1 ? "" : "s"}: ${list}. Create a new key with all required scopes in Settings → API Keys.`,
        );
      }
      pending = { kind: "existing", apiKey: pasted };
    }

    const code = store.create({
      pending,
      redirectUri,
      clientId,
      codeChallenge,
      codeChallengeMethod: "S256",
    });
    const target = new URL(redirectUri);
    target.searchParams.set("code", code);
    if (state) target.searchParams.set("state", state);
    return reply.redirect(target.toString(), 302);
  });

  app.post("/oauth/token", async (req, reply) => {
    // RFC 6749 §5.1 — token responses must not be cached.
    reply.header("Cache-Control", "no-store").header("Pragma", "no-cache");

    const b = (req.body ?? {}) as Record<string, string>;
    if (b.grant_type !== "authorization_code") {
      return reply.status(400).send({
        error: "unsupported_grant_type",
        error_description: "only authorization_code is supported",
      });
    }
    const code = b.code;
    const redirectUri = b.redirect_uri;
    const codeVerifier = b.code_verifier;
    const clientId = b.client_id;

    if (!code || !redirectUri || !codeVerifier) {
      return reply.status(400).send({ error: "invalid_request" });
    }

    const entry = store.consume(code);
    if (!entry) {
      return reply
        .status(400)
        .send({ error: "invalid_grant", error_description: "unknown or expired code" });
    }
    if (entry.redirectUri !== redirectUri) {
      return reply
        .status(400)
        .send({ error: "invalid_grant", error_description: "redirect_uri mismatch" });
    }
    if (clientId && entry.clientId !== clientId) {
      return reply
        .status(400)
        .send({ error: "invalid_grant", error_description: "client_id mismatch" });
    }
    if (!verifyPkceS256(codeVerifier, entry.codeChallenge)) {
      return reply
        .status(400)
        .send({ error: "invalid_grant", error_description: "PKCE verification failed" });
    }

    // Only mint a new key AFTER all validation passes. Abandoned or failed
    // flows leave no trace in the API-key repo.
    let accessToken: string;
    if (entry.pending.kind === "create") {
      accessToken = `sw_${randomBytes(24).toString("hex")}`;
      await apiKeyRepo.create({
        id: randomUUID(),
        accountId: entry.pending.accountId,
        label: entry.pending.label,
        keyHash: hashApiKey(accessToken),
        keyPrefix: accessToken.slice(0, 10),
        scopes: entry.pending.scopes,
      });
    } else {
      accessToken = entry.pending.apiKey;
    }

    return reply.status(200).send({
      access_token: accessToken,
      token_type: "Bearer",
    });
  });

  return {
    destroy: () => store.destroy(),
    _store: store,
  };
}
