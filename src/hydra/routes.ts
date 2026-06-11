// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Hydra integration routes (#217): the login + consent providers (passkey-
 * gated), the mediated DCR endpoint, the Hydra logout/error landing pages, and
 * the OAuth discovery documents. This is the surface that replaces the old
 * src/oauth/ shim — but here ShellWatch is Hydra's identity provider, not a
 * fake AS. The web UI runs its own authorization-code + PKCE flow in the
 * browser (no server-side callback); see the note at the bottom of this file.
 */
import type { FastifyInstance } from "fastify";
import type { Config } from "../config/index.js";
import type { ShellWatchDB } from "../db/connection.js";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import {
  BEARER_PATHS,
  BEARER_SCOPES,
  RESOURCE_METADATA_PATHS,
  WELL_KNOWN_PROTECTED_RESOURCE,
  type BearerScope,
} from "../server/auth/bearer-gate.js";
import { generatePasskeyAssertionOptions, verifyPasskeyAssertion } from "../webauthn/assertion.js";
import type { HydraAdminClient } from "./admin-client.js";
import { renderErrorPage, renderPasskeyPage } from "./render.js";

/** Hydra "remember" durations (seconds). */
const REMEMBER_FOR = 60 * 60 * 24 * 30;

export interface RegisterHydraRoutesParams {
  app: FastifyInstance;
  config: Config;
  /** WebAuthn-capable DB. When null, the passkey login/consent providers are
   * not mounted (DCR + discovery still are). */
  db: ShellWatchDB | null;
  accountRepo: AccountRepository;
  admin: HydraAdminClient;
  rpId: string;
  trustedOrigins: string[];
  /** Whether /agent-proxy is mounted — gates the agent protected-resource doc + agent DCR scope. */
  agentProxyEnabled: boolean;
}

export function registerHydraRoutes(params: RegisterHydraRoutesParams): void {
  const { app, config, db, accountRepo, admin, rpId, trustedOrigins } = params;
  const { agentProxyEnabled } = params;

  // Read at request time — test helpers mutate externalUrl after listen().
  const ext = (): string => config.server.externalUrl.replace(/\/+$/, "");
  const hydraPub = config.hydra.publicUrl.replace(/\/+$/, "");
  const spaClient = config.hydra.spa;

  // Per-route rate limits for the UNAUTHENTICATED passkey provider endpoints.
  // /options enumerate credential ids + mint challenges (and consent/options
  // hits Hydra admin); /verify run WebAuthn crypto. Reuses the same knobs the
  // old login routes had (security.rateLimit.{loginOptions,loginVerify}).
  const rl = config.security.rateLimit;
  const optionsLimit = {
    rateLimit: { max: rl.loginOptions.max, timeWindow: `${rl.loginOptions.windowMinutes} minutes` },
  };
  const verifyLimit = {
    rateLimit: { max: rl.loginVerify.max, timeWindow: `${rl.loginVerify.windowMinutes} minutes` },
  };

  // --- Discovery: RFC 9728 protected-resource + blended AS metadata ---
  // The AS metadata points authorization/token at Hydra (the real issuer) but
  // advertises ShellWatch's *mediated* registration_endpoint — Hydra's own DCR
  // is disabled. MCP clients discover the protected resource here, then this
  // blended doc, then DCR against /oauth/register and auth against Hydra.
  const resourceMetadata = (scope: BearerScope): Record<string, unknown> => ({
    resource: `${ext()}${BEARER_PATHS[scope]}`,
    authorization_servers: [ext()],
    bearer_methods_supported: ["header"],
    scopes_supported: [scope],
  });

  app.get(WELL_KNOWN_PROTECTED_RESOURCE, async () => resourceMetadata("mcp"));
  app.get(RESOURCE_METADATA_PATHS.mcp, async () => resourceMetadata("mcp"));
  if (agentProxyEnabled) {
    app.get(RESOURCE_METADATA_PATHS.agent, async () => resourceMetadata("agent"));
  }

  app.get("/.well-known/oauth-authorization-server", async () => ({
    issuer: hydraPub,
    authorization_endpoint: `${hydraPub}/oauth2/auth`,
    token_endpoint: `${hydraPub}/oauth2/token`,
    registration_endpoint: `${ext()}/oauth/register`,
    jwks_uri: `${hydraPub}/.well-known/jwks.json`,
    revocation_endpoint: `${hydraPub}/oauth2/revoke`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
    scopes_supported: BEARER_SCOPES.filter((s) => s !== "agent" || agentProxyEnabled),
  }));

  // --- Mediated DCR (#217): policy enforced locally, client minted in Hydra ---
  // MCP clients and the agent-client both register here. `agent` is only
  // grantable when the proxy is mounted; the `ui` scope is reserved for the
  // first-party SPA and is never grantable via DCR.
  const dcr = config.hydra.dcr;
  const redirectPatterns = dcr.redirectUriPatterns.map((p) => new RegExp(p));
  const allowedScopes = new Set(
    dcr.allowedScopes.filter((s) => s !== "agent" || agentProxyEnabled),
  );

  app.post<{ Body: Record<string, unknown> }>(
    "/oauth/register",
    {
      config: {
        rateLimit: { max: 10, timeWindow: "15 minutes" },
      },
    },
    async (request, reply) => {
      const body = request.body ?? {};
      const redirectUris = Array.isArray(body.redirect_uris)
        ? (body.redirect_uris as unknown[]).filter((u): u is string => typeof u === "string")
        : [];
      if (redirectUris.length === 0) {
        return reply
          .status(400)
          .send({ error: "invalid_redirect_uri", error_description: "redirect_uris is required" });
      }
      for (const uri of redirectUris) {
        if (!redirectPatterns.some((re) => re.test(uri))) {
          return reply.status(400).send({
            error: "invalid_redirect_uri",
            error_description: `redirect_uri not allowed by policy: ${uri}`,
          });
        }
      }

      // Requested scope ⊆ allowed (default {mcp}); empty → mcp.
      const requested =
        typeof body.scope === "string" && body.scope.trim()
          ? body.scope.trim().split(/\s+/)
          : ["mcp"];
      const granted = requested.filter((s) => allowedScopes.has(s));
      if (granted.length === 0) {
        return reply.status(400).send({
          error: "invalid_scope",
          error_description: `scope must be a subset of: ${[...allowedScopes].join(" ")}`,
        });
      }

      const clientName = typeof body.client_name === "string" ? body.client_name : "MCP Client";
      try {
        // Public client, PKCE-enforced by Hydra (no secret). Omit client_id so
        // Hydra assigns one.
        // Always allow `offline` so clients can obtain a refresh token (the
        // agent-client + long-lived MCP sessions rely on silent renewal). The
        // resource scope (mcp/agent) is still policy-gated above.
        const clientScope = [...granted, "offline"].join(" ");
        const created = await admin.createClient({
          client_name: clientName,
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
          scope: clientScope,
          redirect_uris: redirectUris,
          token_endpoint_auth_method: "none",
        });
        return reply.status(201).send({
          client_id: created.client_id,
          client_id_issued_at: Math.floor(Date.now() / 1000),
          token_endpoint_auth_method: "none",
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
          redirect_uris: created.redirect_uris ?? redirectUris,
          scope: created.scope ?? clientScope,
          client_name: clientName,
        });
      } catch (err) {
        request.log.error(err, "mediated DCR failed");
        return reply
          .status(502)
          .send({ error: "server_error", error_description: "client registration failed" });
      }
    },
  );

  // --- Login + consent providers (passkey-gated) — require the WebAuthn DB ---
  if (db) {
    app.get<{ Querystring: { login_challenge?: string } }>(
      "/api/hydra/login",
      async (request, reply) => {
        const challenge = request.query.login_challenge;
        if (!challenge)
          return reply
            .status(400)
            .type("text/html")
            .send(renderErrorPage("missing_login_challenge"));
        const loginReq = await admin.getLoginRequest(challenge);
        if (loginReq.skip) {
          const { redirect_to } = await admin.acceptLoginRequest(challenge, {
            subject: loginReq.subject,
          });
          return reply.redirect(redirect_to);
        }
        return reply.type("text/html; charset=utf-8").send(
          renderPasskeyPage({
            title: "Sign in · ShellWatch",
            description: "Authenticate with your passkey to continue.",
            optionsUrl: "/api/hydra/login/options",
            verifyUrl: "/api/hydra/login/verify",
            extra: { login_challenge: challenge },
          }),
        );
      },
    );

    app.post("/api/hydra/login/options", { config: optionsLimit }, async () => {
      const result = await generatePasskeyAssertionOptions({ db, rpId });
      if (!result) return { error: "no_passkeys" };
      return { ...result.options, challengeId: result.challengeId };
    });

    app.post<{ Body: { login_challenge: string; challengeId: string; credential: unknown } }>(
      "/api/hydra/login/verify",
      { config: verifyLimit },
      async (request, reply) => {
        const { login_challenge: challenge, challengeId, credential } = request.body;
        if (!challenge) {
          reply.status(400);
          return { error: "missing login_challenge" };
        }
        const verified = await verifyPasskeyAssertion({
          db,
          accountRepo,
          rpId,
          trustedOrigins,
          challengeId,
          credential,
        });
        if (!verified.ok) {
          reply.status(verified.status);
          return { error: verified.error };
        }
        const { redirect_to } = await admin.acceptLoginRequest(challenge, {
          subject: verified.accountId,
          remember: true,
          remember_for: REMEMBER_FOR,
        });
        return { redirectTo: redirect_to };
      },
    );

    // --- Consent provider (passkey step-up; the first-party SPA auto-accepts) ---
    app.get<{ Querystring: { consent_challenge?: string } }>(
      "/api/hydra/consent",
      async (request, reply) => {
        const challenge = request.query.consent_challenge;
        if (!challenge) {
          return reply
            .status(400)
            .type("text/html")
            .send(renderErrorPage("missing_consent_challenge"));
        }
        const consentReq = await admin.getConsentRequest(challenge);
        const isFirstParty = consentReq.client.client_id === spaClient.clientId;
        if (isFirstParty || consentReq.skip) {
          const { redirect_to } = await admin.acceptConsentRequest(challenge, {
            grant_scope: consentReq.requested_scope,
            grant_access_token_audience: consentReq.requested_access_token_audience,
            remember: true,
            remember_for: REMEMBER_FOR,
          });
          return reply.redirect(redirect_to);
        }
        const clientName = consentReq.client.client_name || consentReq.client.client_id;
        return reply.type("text/html; charset=utf-8").send(
          renderPasskeyPage({
            title: "Authorize · ShellWatch",
            description: "Approve this request with your passkey.",
            optionsUrl: "/api/hydra/consent/options",
            verifyUrl: "/api/hydra/consent/verify",
            extra: { consent_challenge: challenge },
            clientName,
            scopes: consentReq.requested_scope,
            buttonLabel: "Approve with passkey",
          }),
        );
      },
    );

    app.post<{ Body: { consent_challenge: string } }>(
      "/api/hydra/consent/options",
      { config: optionsLimit },
      async (request, reply) => {
        const challenge = request.body?.consent_challenge;
        if (typeof challenge !== "string" || !challenge) {
          reply.status(400);
          return { error: "missing consent_challenge" };
        }
        // A bogus/expired challenge makes Hydra's admin API throw — return a
        // clean 400 instead of an unhandled 500 on this unauthenticated route.
        let consentReq: Awaited<ReturnType<typeof admin.getConsentRequest>>;
        try {
          consentReq = await admin.getConsentRequest(challenge);
        } catch {
          reply.status(400);
          return { error: "invalid consent_challenge" };
        }
        const result = await generatePasskeyAssertionOptions({
          db,
          rpId,
          accountId: consentReq.subject,
        });
        if (!result) return { error: "no_passkeys" };
        return { ...result.options, challengeId: result.challengeId };
      },
    );

    app.post<{ Body: { consent_challenge: string; challengeId: string; credential: unknown } }>(
      "/api/hydra/consent/verify",
      { config: verifyLimit },
      async (request, reply) => {
        const { consent_challenge: challenge, challengeId, credential } = request.body;
        if (typeof challenge !== "string" || !challenge) {
          reply.status(400);
          return { error: "missing consent_challenge" };
        }
        let consentReq: Awaited<ReturnType<typeof admin.getConsentRequest>>;
        try {
          consentReq = await admin.getConsentRequest(challenge);
        } catch {
          reply.status(400);
          return { error: "invalid consent_challenge" };
        }
        const verified = await verifyPasskeyAssertion({
          db,
          accountRepo,
          rpId,
          trustedOrigins,
          challengeId,
          credential,
          // Consent must be approved by the very subject Hydra is asking about.
          expectedAccountId: consentReq.subject,
        });
        if (!verified.ok) {
          reply.status(verified.status);
          return { error: verified.error };
        }
        const { redirect_to } = await admin.acceptConsentRequest(challenge, {
          grant_scope: consentReq.requested_scope,
          grant_access_token_audience: consentReq.requested_access_token_audience,
          remember: true,
          remember_for: REMEMBER_FOR,
        });
        return { redirectTo: redirect_to };
      },
    );
  } // end if (db) — login + consent providers

  // --- Hydra logout + error landing pages ---
  app.get<{ Querystring: { logout_challenge?: string } }>(
    "/api/hydra/logout",
    async (request, reply) => {
      const challenge = request.query.logout_challenge;
      if (!challenge) return reply.redirect("/login");
      const { redirect_to } = await admin.acceptLogoutRequest(challenge);
      return reply.redirect(redirect_to);
    },
  );

  app.get<{ Querystring: { error?: string; error_description?: string } }>(
    "/api/hydra/error",
    async (request, reply) => {
      return reply
        .type("text/html; charset=utf-8")
        .send(renderErrorPage(request.query.error ?? "error", request.query.error_description));
    },
  );

  // No server-side login/callback routes for the web UI: the SPA runs the
  // authorization-code + PKCE flow itself, in the browser, against Hydra's
  // public endpoints (`${hydraPub}/oauth2/{auth,token}`) using the first-party
  // public client `${spaClient.clientId}`. The SPA's bootstrap config exposes
  // those values (see /config.js).
}
