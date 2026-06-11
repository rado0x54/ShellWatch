// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { resolve } from "node:path";
import fastifyCors from "@fastify/cors";
import fastifyRateLimit from "@fastify/rate-limit";
import fastifyStatic from "@fastify/static";
import fastifyWebsocket from "@fastify/websocket";
import Fastify from "fastify";
import type { Config } from "../config/index.js";
import type { ShellWatchDB } from "../db/connection.js";
import type {
  AccountRepository,
  EndpointRepository,
  PushSubscriptionRepository,
  SshKeyRepository,
} from "../db/index.js";
import type { SessionLifecycleRepository, SigningRequestsRepository } from "../audit/index.js";
import { registerAgentProxyRoute } from "../agent-socket/index.js";
import { createDemoEndpointsService } from "../demo-endpoints/index.js";
import { registerMcpHttpTransport } from "../mcp/http-transport.js";
import type { PendingActionStore } from "../pending-action/index.js";
import type { WebSocketChannel } from "../pending-action/index.js";
import type { TerminalManager } from "../terminal/index.js";
import type { KeyAvailability, PrivateKeyProvider } from "../transport/key-directory-watcher.js";
import type { ScannedKey } from "../transport/key-scanner.js";
import { registerWebAuthnRoutes } from "../webauthn/index.js";
import type { HydraAdminClient } from "../hydra/admin-client.js";
import { createBearerResolver } from "../hydra/bearer-resolver.js";
import { registerHydraRoutes } from "../hydra/routes.js";
import type { AccountLifecycle } from "./account-lifecycle.js";
import { buildInfo } from "./buildInfo.js";
import { BEARER_PATHS, UI_SCOPE, registerBearerGate } from "./auth/bearer-gate.js";
import { registerIpAllowlist } from "./auth/ip-allowlist.js";
import { registerAccountRoutes } from "./routes/accounts.js";
import { registerActionRoutes } from "./routes/actions.js";
import { registerAuditRoutes } from "./routes/audit.js";
import { registerEndpointRoutes } from "./routes/endpoints.js";
import { registerSessionRoutes } from "./routes/sessions.js";
import { registerPushRoutes } from "./routes/push.js";
import { registerSshKeyRoutes } from "./routes/ssh-keys.js";
import type { WsExtension } from "./ws-extension.js";
import { registerWebSocket } from "./ws-handler.js";

export interface AppOptions {
  logger?: boolean;
  skipStaticFiles?: boolean;
}

export interface BuildAppParams {
  config: Config;
  terminalManager: TerminalManager;
  endpointRepo: EndpointRepository;
  keyRepo: SshKeyRepository;
  accountRepo: AccountRepository;
  accountLifecycle: AccountLifecycle;
  db?: ShellWatchDB | null;
  wsExtensions?: WsExtension[];
  keyAvailability?: KeyAvailability | null;
  /** Hydra admin client (#217). Tests inject a fake; production wires the HTTP client. */
  hydraAdmin: HydraAdminClient;
  /** Session-lifecycle audit repo (#184). When omitted, /api/audit/sessions is not registered. */
  sessionLifecycleRepo?: SessionLifecycleRepository;
  /** Signing-request audit repo (#186). When omitted, /api/audit/signings is not registered. */
  signingRequestsRepo?: SigningRequestsRepository;
  options?: AppOptions;
  /** PendingAction store + WebSocket channel for sign request notifications */
  actionStore?: PendingActionStore;
  wsChannel?: WebSocketChannel;
  /** Push subscription repo for Web Push routes */
  pushSubRepo?: PushSubscriptionRepository;
  /** Required when agentSocket.proxyEnabled is true */
  agentProxy?: {
    keyProvider: PrivateKeyProvider & { getAvailableKeys(): ScannedKey[] };
    signingBridge?: import("../webauthn/signing-bridge.js").SigningBridge;
    findCredentialsForAccount?: (
      accountId: string,
    ) => import("../db/repositories/credential-queries.js").WebAuthnCredentialInfo[];
    rpId: string;
  };
}

export async function buildApp(params: BuildAppParams) {
  const {
    config,
    terminalManager,
    endpointRepo,
    keyRepo,
    accountRepo,
    accountLifecycle,
    db = null,
    wsExtensions = [],
    keyAvailability = null,
    hydraAdmin,
    options = {},
  } = params;

  const app = Fastify({
    logger: options.logger ?? true,
    trustProxy: config.server.trustProxy,
  });

  await app.register(fastifyCors, { origin: true });
  await app.register(fastifyRateLimit, { global: false });
  await app.register(fastifyWebsocket);

  // Decorate request with accountId + apiKey. accountId defaults to "" — the
  // bearer gate overwrites it with a real account id before any protected
  // handler runs; exempt/static routes never read it. apiKey holds the
  // introspected OAuth principal (null on exempt routes).
  app.decorateRequest("accountId", "");
  app.decorateRequest("apiKey", null);

  // Single auth gate (#217): every authenticated surface presents a Hydra
  // opaque access token, validated via introspection (sub → account, scope per
  // path: ui for /api+/ws, mcp for /mcp, agent for /agent-proxy). IP allowlist
  // still fronts /mcp.
  registerIpAllowlist(app, config.security.allowedNetworks, [BEARER_PATHS.mcp]);
  const agentProxyEnabled = config.agentSocket.proxyEnabled;
  const resolveBearer = createBearerResolver({
    admin: hydraAdmin,
    cacheTtlMs: config.hydra.introspectionCacheTtlMs,
  });
  registerBearerGate({ app, resolveBearer, accountRepo, config, agentProxyEnabled });

  // Hydra integration: mediated DCR + discovery (always), plus the passkey
  // login + consent providers (only when the WebAuthn-capable db is present —
  // the bearer-only test harness runs without one).
  registerHydraRoutes({
    app,
    config,
    db,
    accountRepo,
    admin: hydraAdmin,
    rpId: config.security.rpId,
    trustedOrigins: config.security.trustedWebauthnOrigins,
    agentProxyEnabled,
  });

  app.get("/health", async () => ({ status: "ok" }));

  // Build identity — operator affordance, curl-able without auth so deployments
  // can be sanity-checked. The SPA reads window.__BUILD_INFO__ injected via
  // /config.js instead; this route is not the source of truth for the UI. The
  // same payload is already in /config.js (also unauth, bootstraps the login
  // page), so /api/version reveals nothing additional.
  app.get("/api/version", async () => buildInfo);

  // App-level event bus — accountLifecycle is constructed in DI root (index.ts)
  // so the periodic cleanup job in cleanup.ts can also publish to it. Listener
  // order is not load-bearing: AgentSession.destroy is robust to its sessions
  // having already been closed by TerminalManager.closeAllForAccount.
  accountLifecycle.on("deleted", ({ accountId }) => {
    try {
      const closed = terminalManager.closeAllForAccount(accountId, "account-deleted");
      if (closed > 0) {
        app.log.info(`Closed ${closed} session(s) for deleted account ${accountId}`);
      }
    } catch (err) {
      app.log.error(err, `Failed to close terminals for deleted account ${accountId}`);
    }
    // Revoke the subject's Hydra login + consent sessions so any live grant
    // (web UI, MCP, agent) for this account dies too (#217). Tokens are keyed
    // to sub = accountId, so revoking the subject's sessions covers them all.
    void Promise.allSettled([
      hydraAdmin.revokeLoginSessions(accountId),
      hydraAdmin.revokeConsentSessions(accountId),
    ]).then((results) => {
      for (const r of results) {
        if (r.status === "rejected") {
          app.log.warn(
            r.reason,
            `Failed to revoke Hydra sessions for deleted account ${accountId}`,
          );
        }
      }
    });
  });

  // Virtual demo-endpoints: synthesized from config.demoEndpoints, merged into
  // each account's endpoint list when accounts.show_demo_endpoints is true.
  // Never copied into the endpoints table — config is the source of truth.
  const demoEndpoints = createDemoEndpointsService(config.demoEndpoints);

  // --- REST API routes ---
  registerAccountRoutes({ app, accountRepo, demoEndpoints, db, accountLifecycle });
  registerSshKeyRoutes({ app, keyRepo, accountRepo, keyAvailability });
  registerEndpointRoutes({ app, endpointRepo, accountRepo, demoEndpoints, terminalManager });

  const wsHandler = registerWebSocket({ app, terminalManager });
  for (const ext of wsExtensions) wsHandler.addExtension(ext);

  registerSessionRoutes({
    app,
    endpointRepo,
    accountRepo,
    demoEndpoints,
    terminalManager,
  });

  if (params.actionStore && params.wsChannel) {
    registerActionRoutes({
      app,
      actionStore: params.actionStore,
      wsChannel: params.wsChannel,
    });
  }

  if (params.sessionLifecycleRepo || params.signingRequestsRepo) {
    registerAuditRoutes({
      app,
      sessionLifecycleRepo: params.sessionLifecycleRepo,
      signingRequestsRepo: params.signingRequestsRepo,
    });
  }

  if (params.pushSubRepo) {
    registerPushRoutes({
      app,
      pushSubRepo: params.pushSubRepo,
    });
  }

  // MCP server over streamable HTTP at /mcp
  await registerMcpHttpTransport({
    app,
    config,
    terminalManager,
    endpointRepo,
    demoEndpoints,
    keyRepo,
    accountRepo,
    accountLifecycle,
  });

  // WebAuthn routes
  if (db) {
    registerWebAuthnRoutes({
      app,
      db,
      accountRepo,
      rpId: config.security.rpId,
      trustedOrigins: config.security.trustedWebauthnOrigins,
      selfRegistrationEnabled: config.security.selfRegistrationEnabled,
      rateLimitConfig: config.security.rateLimit,
    });
  }

  // Agent proxy WebSocket route (for remote SSH agent clients)
  if (config.agentSocket.proxyEnabled && params.agentProxy) {
    registerAgentProxyRoute({
      app,
      keyProvider: params.agentProxy.keyProvider,
      signingBridge: params.agentProxy.signingBridge,
      findCredentialsForAccount: params.agentProxy.findCredentialsForAccount,
      rpId: params.agentProxy.rpId,
    });
    app.log.info("Agent proxy endpoint enabled at /agent-proxy");
  }

  // Client runtime config
  app.get("/config.js", async (_request, reply) => {
    reply.type("application/javascript");
    const vapidPublicKey = config.vapid?.publicKey ?? null;
    // OAuth bootstrap for the browser PKCE client (#217): the issuer, the
    // first-party public client id, its redirect URI, and the scope to request.
    const oauth = {
      issuer: config.hydra.publicUrl.replace(/\/+$/, ""),
      clientId: config.hydra.spa.clientId,
      redirectUri:
        config.hydra.spa.redirectUri ??
        `${config.server.externalUrl.replace(/\/+$/, "")}/auth/callback`,
      scope: `openid offline ${UI_SCOPE}`,
    };
    return [
      `window.__SELF_REGISTRATION_ENABLED__=${JSON.stringify(config.security.selfRegistrationEnabled)};`,
      `window.__VAPID_PUBLIC_KEY__=${JSON.stringify(vapidPublicKey)};`,
      `window.__BUILD_INFO__=${JSON.stringify(buildInfo)};`,
      `window.__OAUTH__=${JSON.stringify(oauth)};`,
    ].join("");
  });

  // Static client files (built by SvelteKit adapter-static -> dist/client/)
  if (!options.skipStaticFiles) {
    const clientDist = resolve(process.cwd(), "dist/client");
    await app.register(fastifyStatic, { root: clientDist, prefix: "/" });

    // SPA fallback: serve index.html for client-side routing
    app.setNotFoundHandler((_request, reply) => {
      reply.sendFile("index.html");
    });
  }

  return app;
}
