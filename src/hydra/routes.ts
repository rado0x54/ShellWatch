// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Hydra integration routes (#217): the login + consent providers (passkey-
 * gated), the mediated DCR endpoint, the Hydra logout/error landing pages, and
 * the OAuth discovery documents. This is the surface that replaces the old
 * src/oauth/ shim — but here ShellWatch is Hydra's identity provider, not a
 * fake AS. The web UI runs its own authorization-code + PKCE flow in the
 * browser (no server-side callback); see the note at the bottom of this file.
 */
import type { FastifyInstance, FastifyReply, FastifyRequest, RouteGenericInterface } from "fastify";
import type { Config } from "../config/index.js";
import type { ShellWatchDB } from "../db/connection.js";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import { hasPasskeys } from "../db/repositories/index.js";
import {
  BEARER_PATHS,
  BEARER_SCOPES,
  RESOURCE_METADATA_PATHS,
  WELL_KNOWN_PROTECTED_RESOURCE,
  type BearerScope,
} from "../server/auth/bearer-gate.js";
import { generatePasskeyAssertionOptions, verifyPasskeyAssertion } from "../webauthn/assertion.js";
import { type HydraAdminClient, HydraApiError } from "./admin-client.js";
import { renderApprovePage, renderErrorPage, renderPasskeyPage } from "./render.js";

/** Hydra "remember" durations (seconds). */
const REMEMBER_FOR = 60 * 60 * 24 * 30;

/**
 * Raised inside a provider flow when a Hydra admin call fails on bad input — a
 * bogus, expired, replayed, or forged challenge. The route wrappers below turn
 * it into a clean 4xx instead of letting it bubble up as an unhandled 500.
 * Genuinely unexpected failures (network down, our bug) are NOT wrapped, so
 * those still surface as 500s and get logged.
 */
class FlowError extends Error {
  constructor(public reason: string) {
    super(reason);
    this.name = "FlowError";
  }
}

/**
 * Run a Hydra admin call inside a provider flow. A `HydraApiError` (Hydra
 * rejected the challenge) becomes a `FlowError(reason)` the wrapper renders as
 * 400; anything else propagates untouched. This is the single chokepoint that
 * stops a junk/expired challenge from 500-ing the unauthenticated provider
 * routes (and amplifying unthrottled admin round-trips).
 */
async function hydra<T>(p: Promise<T>, reason: string): Promise<T> {
  try {
    return await p;
  } catch (err) {
    if (err instanceof HydraApiError) throw new FlowError(reason);
    throw err;
  }
}

/**
 * Wrap an HTML provider-page handler: a `FlowError` renders the styled error
 * page with a 400 instead of surfacing a 500. The route generic is threaded
 * through so `request.query`/`request.params` stay typed.
 */
function htmlFlow<R extends RouteGenericInterface>(
  handler: (request: FastifyRequest<R>, reply: FastifyReply) => Promise<unknown>,
) {
  return async (request: FastifyRequest<R>, reply: FastifyReply): Promise<unknown> => {
    try {
      return await handler(request, reply);
    } catch (err) {
      if (err instanceof FlowError) {
        return reply.status(400).type("text/html; charset=utf-8").send(renderErrorPage(err.reason));
      }
      throw err;
    }
  };
}

/** Wrap a JSON provider endpoint: a `FlowError` becomes `{ error }` with 400. */
function jsonFlow<R extends RouteGenericInterface>(
  handler: (request: FastifyRequest<R>, reply: FastifyReply) => Promise<unknown>,
) {
  return async (request: FastifyRequest<R>, reply: FastifyReply): Promise<unknown> => {
    try {
      return await handler(request, reply);
    } catch (err) {
      if (err instanceof FlowError) {
        reply.status(400);
        return { error: err.reason };
      }
      throw err;
    }
  };
}

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
    app.get(
      "/api/hydra/login",
      { config: optionsLimit },
      htmlFlow<{ Querystring: { login_challenge?: string } }>(async (request, reply) => {
        const challenge = request.query.login_challenge;
        if (!challenge) throw new FlowError("missing_login_challenge");
        const loginReq = await hydra(admin.getLoginRequest(challenge), "invalid_login_challenge");
        if (loginReq.skip) {
          // Remembered session — no passkey performed, so mark the login NOT
          // fresh. The consent step reads this to decide passkey vs. approve.
          const { redirect_to } = await hydra(
            admin.acceptLoginRequest(challenge, {
              subject: loginReq.subject,
              context: { freshLogin: false },
            }),
            "login_flow_expired",
          );
          return reply.redirect(redirect_to);
        }
        // This page is now the sole login landing (the SPA no longer ships a
        // /login mask). Show a create-account link under the same rule the
        // /register flow uses — first-run bootstrap (no passkeys) or self-
        // registration — and drop the passkey button entirely when there's
        // nothing to sign in with yet.
        const passkeysExist = hasPasskeys(db);
        const canRegister = !passkeysExist || config.security.selfRegistrationEnabled;
        return reply.type("text/html; charset=utf-8").send(
          renderPasskeyPage({
            title: "Sign in · ShellWatch",
            description: passkeysExist
              ? "Authenticate with your passkey to continue."
              : "No passkeys yet — create an account to get started.",
            optionsUrl: "/api/hydra/login/options",
            verifyUrl: "/api/hydra/login/verify",
            extra: { login_challenge: challenge },
            showButton: passkeysExist,
            registerUrl: canRegister ? "/register" : undefined,
          }),
        );
      }),
    );

    app.post("/api/hydra/login/options", { config: optionsLimit }, async () => {
      const result = await generatePasskeyAssertionOptions({ db, rpId });
      if (!result) return { error: "no_passkeys" };
      return { ...result.options, challengeId: result.challengeId };
    });

    app.post(
      "/api/hydra/login/verify",
      { config: verifyLimit },
      jsonFlow<{ Body: { login_challenge?: string; challengeId?: string; credential?: unknown } }>(
        async (request, reply) => {
          // Read defensively — a bodyless POST leaves request.body undefined, so
          // destructuring first would TypeError → unauthenticated 500.
          const challenge = request.body?.login_challenge;
          if (typeof challenge !== "string" || !challenge) {
            throw new FlowError("missing login_challenge");
          }
          const verified = await verifyPasskeyAssertion({
            db,
            accountRepo,
            rpId,
            trustedOrigins,
            challengeId: request.body?.challengeId ?? "",
            credential: request.body?.credential,
          });
          if (!verified.ok) {
            reply.status(verified.status);
            return { error: verified.error };
          }
          // Stale challenge after a successful ceremony would otherwise 500 with
          // the assertion already burned — surface a clean "restart" instead.
          const { redirect_to } = await hydra(
            admin.acceptLoginRequest(challenge, {
              subject: verified.accountId,
              remember: true,
              remember_for: REMEMBER_FOR,
              // Passkey just performed in this flow — lets the consent step skip
              // a redundant second passkey (option-1).
              context: { freshLogin: true },
            }),
            "login_flow_expired",
          );
          return { redirectTo: redirect_to };
        },
      ),
    );

    // --- Consent provider (passkey step-up; the first-party SPA auto-accepts) ---
    app.get(
      "/api/hydra/consent",
      { config: optionsLimit },
      htmlFlow<{ Querystring: { consent_challenge?: string } }>(async (request, reply) => {
        const challenge = request.query.consent_challenge;
        if (!challenge) throw new FlowError("missing_consent_challenge");
        const consentReq = await hydra(
          admin.getConsentRequest(challenge),
          "invalid_consent_challenge",
        );
        const isFirstParty = consentReq.client.client_id === spaClient.clientId;
        if (isFirstParty || consentReq.skip) {
          const { redirect_to } = await hydra(
            admin.acceptConsentRequest(challenge, {
              grant_scope: consentReq.requested_scope,
              grant_access_token_audience: consentReq.requested_access_token_audience,
              remember: true,
              remember_for: REMEMBER_FOR,
            }),
            "consent_flow_expired",
          );
          return reply.redirect(redirect_to);
        }
        const clientName = consentReq.client.client_name || consentReq.client.client_id;
        // Option-1: a passkey performed at login moments ago (same flow) is
        // enough presence proof — authorizing the client is an explicit Approve
        // click, not a second passkey. A remembered login (freshLogin !== true)
        // still requires the passkey here: it's the only human gate in that flow.
        const freshLogin = consentReq.context?.freshLogin === true;
        if (freshLogin) {
          return reply.type("text/html; charset=utf-8").send(
            renderApprovePage({
              title: "Authorize · ShellWatch",
              description: "Approve this request to continue.",
              approveUrl: "/api/hydra/consent/approve",
              extra: { consent_challenge: challenge },
              clientName,
              scopes: consentReq.requested_scope,
              buttonLabel: "Approve",
            }),
          );
        }
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
      }),
    );

    app.post(
      "/api/hydra/consent/options",
      { config: optionsLimit },
      jsonFlow<{ Body: { consent_challenge?: string } }>(async (request) => {
        const challenge = request.body?.consent_challenge;
        if (typeof challenge !== "string" || !challenge) {
          throw new FlowError("missing consent_challenge");
        }
        const consentReq = await hydra(
          admin.getConsentRequest(challenge),
          "invalid consent_challenge",
        );
        const result = await generatePasskeyAssertionOptions({
          db,
          rpId,
          accountId: consentReq.subject,
        });
        if (!result) return { error: "no_passkeys" };
        return { ...result.options, challengeId: result.challengeId };
      }),
    );

    app.post(
      "/api/hydra/consent/verify",
      { config: verifyLimit },
      jsonFlow<{
        Body: { consent_challenge?: string; challengeId?: string; credential?: unknown };
      }>(async (request, reply) => {
        // Read defensively — see login/verify.
        const challenge = request.body?.consent_challenge;
        if (typeof challenge !== "string" || !challenge) {
          throw new FlowError("missing consent_challenge");
        }
        const consentReq = await hydra(
          admin.getConsentRequest(challenge),
          "invalid consent_challenge",
        );
        const verified = await verifyPasskeyAssertion({
          db,
          accountRepo,
          rpId,
          trustedOrigins,
          challengeId: request.body?.challengeId ?? "",
          credential: request.body?.credential,
          // Consent must be approved by the very subject Hydra is asking about.
          expectedAccountId: consentReq.subject,
        });
        if (!verified.ok) {
          reply.status(verified.status);
          return { error: verified.error };
        }
        const { redirect_to } = await hydra(
          admin.acceptConsentRequest(challenge, {
            grant_scope: consentReq.requested_scope,
            grant_access_token_audience: consentReq.requested_access_token_audience,
            remember: true,
            remember_for: REMEMBER_FOR,
          }),
          "consent_flow_expired",
        );
        return { redirectTo: redirect_to };
      }),
    );

    // No-passkey consent grant (option-1). Only valid when the login in this
    // very flow was a fresh passkey ceremony — re-checked server-side against
    // Hydra's record below, so a remembered-login flow can't take this path
    // (it must use /consent/verify with a passkey). The client can't forge
    // `freshLogin`; we stamped it into the login context.
    app.post(
      "/api/hydra/consent/approve",
      { config: optionsLimit },
      jsonFlow<{ Body: { consent_challenge?: string } }>(async (request) => {
        const challenge = request.body?.consent_challenge;
        if (typeof challenge !== "string" || !challenge) {
          throw new FlowError("missing consent_challenge");
        }
        const consentReq = await hydra(
          admin.getConsentRequest(challenge),
          "invalid consent_challenge",
        );
        if (consentReq.context?.freshLogin !== true) {
          // Login wasn't fresh (remembered session) — the passkey gate applies.
          throw new FlowError("passkey_required");
        }
        const { redirect_to } = await hydra(
          admin.acceptConsentRequest(challenge, {
            grant_scope: consentReq.requested_scope,
            grant_access_token_audience: consentReq.requested_access_token_audience,
            remember: true,
            remember_for: REMEMBER_FOR,
          }),
          "consent_flow_expired",
        );
        return { redirectTo: redirect_to };
      }),
    );
  } // end if (db) — login + consent providers

  // --- Hydra logout + error landing pages ---
  app.get<{ Querystring: { logout_challenge?: string } }>(
    "/api/hydra/logout",
    { config: optionsLimit },
    async (request, reply) => {
      const challenge = request.query.logout_challenge;
      if (!challenge) return reply.redirect("/login");
      // A stale/replayed logout_challenge (e.g. back button) shouldn't 500 —
      // logout is forgiving, so fall back to /login on any Hydra rejection.
      try {
        const logoutReq = await hydra(admin.getLogoutRequest(challenge), "logout_flow_expired");
        // Only honor a logout Hydra attributes to a relying party via a valid
        // `id_token_hint` (→ `client` populated). ShellWatch's own logout()
        // always sends the hint, so legitimate sign-outs pass. An unhinted
        // navigation to Hydra's end-session endpoint (logout CSRF) has no
        // client — reject it rather than silently terminating the victim's
        // session.
        if (!logoutReq.client?.client_id) {
          await hydra(admin.rejectLogoutRequest(challenge), "logout_flow_expired");
          return reply.redirect("/login");
        }
        const { redirect_to } = await hydra(
          admin.acceptLogoutRequest(challenge),
          "logout_flow_expired",
        );
        return reply.redirect(redirect_to);
      } catch (err) {
        if (err instanceof FlowError) return reply.redirect("/login");
        throw err;
      }
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
