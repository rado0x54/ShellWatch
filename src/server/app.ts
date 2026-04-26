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
  ApiKeyAuthRepository,
  EndpointRepository,
  PushSubscriptionRepository,
  SshKeyRepository,
} from "../db/index.js";
import { registerAgentProxyRoute } from "../agent-socket/index.js";
import { registerMcpHttpTransport } from "../mcp/http-transport.js";
import type { PendingActionStore } from "../pending-action/index.js";
import type { WebSocketChannel } from "../pending-action/index.js";
import type { TerminalManager } from "../terminal/index.js";
import type { KeyAvailability, PrivateKeyProvider } from "../transport/key-directory-watcher.js";
import type { ScannedKey } from "../transport/key-scanner.js";
import { registerWebAuthnRoutes } from "../webauthn/index.js";
import { registerOAuth } from "../oauth/index.js";
import { registerAuthGate } from "./auth/auth-gate.js";
import { registerBearerGate } from "./auth/bearer-gate.js";
import { registerIpAllowlist } from "./auth/ip-allowlist.js";
import { registerAccountRoutes } from "./routes/accounts.js";
import { registerActionRoutes } from "./routes/actions.js";
import { registerApiKeyRoutes } from "./routes/api-keys.js";
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
  db?: ShellWatchDB | null;
  wsExtensions?: WsExtension[];
  keyAvailability?: KeyAvailability | null;
  apiKeyRepo: ApiKeyAuthRepository;
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

  // IP allowlist + bearer-gate (covers /mcp and /agent-proxy) + OAuth shim.
  registerIpAllowlist(app, config.security.allowedNetworks, ["/mcp"]);
  const mcpPath = "/mcp";
  registerBearerGate({
    app,
    apiKeyRepo,
    accountRepo,
    config,
    paths: {
      [mcpPath]: { requiredScope: "mcp", failureFormat: "rfc6750" },
      "/agent-proxy": { requiredScope: "agent", failureFormat: "plain" },
    },
  });
  const oauth = registerOAuth({ app, apiKeyRepo, config, mcpPath });
  app.addHook("onClose", async () => oauth.destroy());

  app.get("/health", async () => ({ status: "ok" }));

  // --- REST API routes ---
  registerAccountRoutes({ app, accountRepo, db });
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
    return `window.__SELF_REGISTRATION_ENABLED__=${JSON.stringify(config.security.selfRegistrationEnabled)};window.__VAPID_PUBLIC_KEY__=${JSON.stringify(vapidPublicKey)};`;
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
