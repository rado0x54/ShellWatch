import { randomBytes } from "node:crypto";
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
// Deep import: ApiKeyAuthRepository is not part of the public DB barrel — it's
// the wider handle the bearer gate + OAuth callback need (findByHash). See #136.
import type { ApiKeyAuthRepository } from "../db/repositories/api-key-repo.js";
import type { SessionLifecycleRepository, SigningRequestsRepository } from "../audit/index.js";
import { registerAgentProxyRoute } from "../agent-socket/index.js";
import { registerMcpHttpTransport } from "../mcp/http-transport.js";
import type { PendingActionStore } from "../pending-action/index.js";
import type { WebSocketChannel } from "../pending-action/index.js";
import type { TerminalManager } from "../terminal/index.js";
import type { KeyAvailability, PrivateKeyProvider } from "../transport/key-directory-watcher.js";
import type { ScannedKey } from "../transport/key-scanner.js";
import { registerWebAuthnRoutes } from "../webauthn/index.js";
import { registerOAuth } from "../oauth/index.js";
import type { AccountLifecycle } from "./account-lifecycle.js";
import { buildInfo } from "./buildInfo.js";
import { registerAuthGate } from "./auth/auth-gate.js";
import { BEARER_PATHS, registerBearerGate } from "./auth/bearer-gate.js";
import { registerIpAllowlist } from "./auth/ip-allowlist.js";
import { registerAccountRoutes } from "./routes/accounts.js";
import { registerActionRoutes } from "./routes/actions.js";
import { registerApiKeyRoutes } from "./routes/api-keys.js";
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
  apiKeyRepo: ApiKeyAuthRepository;
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
    apiKeyRepo,
    options = {},
  } = params;

  const app = Fastify({
    logger: options.logger ?? true,
    trustProxy: config.server.trustProxy,
  });

  // Cookie secret for session signing
  const cookieSecret = config.security.cookieSecret ?? randomBytes(32).toString("hex");
  if (!config.security.cookieSecret) {
    app.log.warn("No cookieSecret in config — sessions will not survive server restarts");
  }

  await app.register(fastifyCors, { origin: true });
  await app.register(fastifyRateLimit, { global: false });
  await app.register(fastifyWebsocket);

  // Decorate request with accountId + apiKey. accountId defaults to "" — the
  // cookie auth-gate and the bearer gate both overwrite it with a real account
  // id before any protected handler runs; exempt routes never read it. apiKey
  // is null on cookie-authed and exempt routes; the bearer gate populates it
  // for /mcp and /agent-proxy.
  app.decorateRequest("accountId", "");
  app.decorateRequest("apiKey", null);

  // Auth gate: session-cookie enforcement
  registerAuthGate({
    app,
    secret: cookieSecret,
    accountRepo,
  });

  // IP allowlist + bearer-gate (covers /mcp and, when enabled, /agent-proxy) + OAuth shim.
  registerIpAllowlist(app, config.security.allowedNetworks, [BEARER_PATHS.mcp]);
  // Only gate /agent-proxy when the proxy is actually enabled — otherwise the
  // path 401s at the bearer gate while no route is mounted, which is misleading
  // and lets clients mint agent-scoped keys that are useless.
  const agentProxyEnabled = config.agentSocket.proxyEnabled;
  registerBearerGate({
    app,
    apiKeyRepo,
    accountRepo,
    config,
    paths: {
      [BEARER_PATHS.mcp]: { requiredScope: "mcp" },
      ...(agentProxyEnabled ? { [BEARER_PATHS.agent]: { requiredScope: "agent" } } : {}),
    },
  });
  const oauth = registerOAuth({ app, apiKeyRepo, config, agentProxyEnabled });
  app.addHook("onClose", async () => oauth.destroy());

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
  });

  // --- REST API routes ---
  registerAccountRoutes({ app, accountRepo, db, accountLifecycle });
  registerSshKeyRoutes({ app, keyRepo, accountRepo, keyAvailability });
  registerEndpointRoutes({ app, endpointRepo, accountRepo, terminalManager });

  const wsHandler = registerWebSocket({ app, terminalManager });
  for (const ext of wsExtensions) wsHandler.addExtension(ext);

  registerSessionRoutes({
    app,
    endpointRepo,
    accountRepo,
    terminalManager,
  });

  if (params.actionStore && params.wsChannel) {
    registerActionRoutes({
      app,
      actionStore: params.actionStore,
      wsChannel: params.wsChannel,
    });
  }

  registerApiKeyRoutes({ app, apiKeyRepo });

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
      sessionConfig: { secret: cookieSecret, ttlSeconds: config.security.sessionTtlSeconds },
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
    return [
      `window.__SELF_REGISTRATION_ENABLED__=${JSON.stringify(config.security.selfRegistrationEnabled)};`,
      `window.__VAPID_PUBLIC_KEY__=${JSON.stringify(vapidPublicKey)};`,
      `window.__BUILD_INFO__=${JSON.stringify(buildInfo)};`,
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
