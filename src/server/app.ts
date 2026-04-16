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
  ApiKeyRepository,
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
import { hasPasskeys as hasPasskeysQuery } from "../db/repositories/credential-queries.js";
import { createUiSessionService, registerOAuth } from "../oauth/index.js";
import { createOAuthTokenVerifier } from "../oauth/verifier.js";
import { registerWebAuthnRoutes } from "../webauthn/index.js";
import { createApiKeyVerifier } from "./auth/api-key-verifier.js";
import { registerAuthChain } from "./auth/register-auth-chain.js";
import { registerAuthGate } from "./auth/auth-gate.js";
import { registerIpAllowlist } from "./auth/ip-allowlist.js";
import { registerProtectedResourceMetadata } from "./routes/well-known.js";
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

declare module "fastify" {
  interface FastifyInstance {
    /**
     * In-process handle to the OAuth registration. `null` when the server
     * runs without a database (headless / test harness mode) — every
     * production deployment has it.
     */
    oauth: Awaited<ReturnType<typeof registerOAuth>> | null;
  }
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
  apiKeyRepo?: ApiKeyRepository | null;
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
    apiKeyRepo = null,
    options = {},
  } = params;

  const app = Fastify({
    logger: options.logger ?? true,
    trustProxy: config.server.trustProxy,
  });

  // `cookieSecret` is required whenever the server has a database
  // (which is also the condition under which OAuth is wired). The
  // OAuth signing keys are encrypted at rest with a key derived from
  // cookieSecret; a restart without the same secret makes stored keys
  // undecryptable and the provider refuses to start. Fail fast at
  // boot instead of silently regenerating a key per process.
  if (db && !config.security.cookieSecret) {
    throw new Error(
      "security.cookieSecret is required when the server runs with a database. " +
        "OAuth signing keys are encrypted at rest with a key derived from it; " +
        "without a stable persisted secret, stored keys become undecryptable " +
        "on the next server restart.",
    );
  }
  const cookieSecret = config.security.cookieSecret ?? randomBytes(32).toString("hex");

  await app.register(fastifyCors, { origin: true });
  await app.register(fastifyRateLimit, { global: false });
  await app.register(fastifyWebsocket);

  // Decorate request with accountId (set by auth gate / API key auth)
  app.decorateRequest("accountId", null);

  const normalizedExternalUrl = config.server.externalUrl.replace(/\/$/, "");
  const uiResource = normalizedExternalUrl;
  const mcpResource = `${normalizedExternalUrl}/mcp`;

  // OAuth provider (panva) mounted at /oidc/*. Must run before the auth
  // gate — the gate's verifier needs the provider instance. OAuth is
  // wired whenever we have a DB; the only mode in which OAuth is
  // absent is a `db: null` test harness, which also skips the UI.
  const oauthRegistration = db
    ? await registerOAuth({
        app,
        db,
        config: config.oauth,
        baseUrl: config.server.externalUrl,
        sessionSecret: cookieSecret,
      })
    : null;

  // In-process handle to the OAuth registration. Used by tests, by
  // PR 5c's rolling refresh, and by any later feature that needs the
  // provider / minter without reconstructing them.
  app.decorate("oauth", oauthRegistration);

  // Web UI session owns login mint + logout cookie clearing + grant
  // revocation. Handed to the auth-gate (for logout) and to webauthn
  // (for login handler) so both reach through this one seam.
  const uiSession = oauthRegistration
    ? createUiSessionService({
        provider: oauthRegistration.provider,
        minter: oauthRegistration.minter,
        audience: uiResource,
        scopes: config.oauth.scopes,
      })
    : null;

  // Auth gate: onboarding + login enforcement. Replaces the HMAC cookie
  // path with OAuth token validation.
  if (uiSession && oauthRegistration) {
    registerAuthGate({
      app,
      accountRepo,
      oauthVerifier: createOAuthTokenVerifier(oauthRegistration.provider, {
        expectedResource: () => uiResource,
      }),
      uiSession,
      checkHasPasskeys: db ? () => hasPasskeysQuery(db) : () => true,
    });
  }

  // IP allowlist for /mcp (unchanged).
  registerIpAllowlist(app, config.security.allowedNetworks, ["/mcp"]);

  // RFC 9728 Protected Resource Metadata. Only published when an AS is
  // actually available — emitting the document without an AS behind it
  // would be misleading.
  if (oauthRegistration) {
    registerProtectedResourceMetadata({
      app,
      baseUrl: normalizedExternalUrl,
      scopes: config.oauth.scopes,
      resources: ["/mcp"],
    });
  }

  // Unified auth chain on /mcp. API-key verifier always in play; OAuth
  // verifier folded in only when the provider is mounted. Replaces the
  // previous registerApiKeyAuth hook with the same external contract for
  // API-key users (Authorization: Bearer sw_… still works) plus new
  // support for X-API-Key and opaque OAuth tokens.
  if (apiKeyRepo) {
    registerAuthChain({
      app,
      protectedPath: "/mcp",
      apiKeyVerifier: createApiKeyVerifier(apiKeyRepo, accountRepo),
      oauthVerifier: oauthRegistration
        ? createOAuthTokenVerifier(oauthRegistration.provider, {
            expectedResource: () => mcpResource,
          })
        : undefined,
      resourceMetadataUrl: oauthRegistration
        ? `${normalizedExternalUrl}/.well-known/oauth-protected-resource`
        : undefined,
    });
  }

  app.get("/health", async () => ({ status: "ok" }));

  // --- REST API routes ---
  registerAccountRoutes({ app, accountRepo, db });
  registerSshKeyRoutes({ app, keyRepo, accountRepo, keyAvailability });
  registerEndpointRoutes({ app, endpointRepo, accountRepo, terminalManager });

  // Shared set tracking UI-created sessions (used by both WS handler and session routes)
  const uiCreatedSessions = new Set<string>();

  const wsHandler = registerWebSocket(app, terminalManager, uiCreatedSessions);
  for (const ext of wsExtensions) wsHandler.addExtension(ext);

  registerSessionRoutes({
    app,
    endpointRepo,
    accountRepo,
    terminalManager,
    uiCreatedSessions,
  });

  if (params.actionStore && params.wsChannel) {
    registerActionRoutes({
      app,
      actionStore: params.actionStore,
      wsChannel: params.wsChannel,
    });
  }

  if (apiKeyRepo) {
    registerApiKeyRoutes({ app, apiKeyRepo });
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
  });

  // WebAuthn routes
  if (db) {
    registerWebAuthnRoutes({
      app,
      db,
      accountRepo,
      rpId: config.security.rpId,
      trustedOrigins: config.security.trustedWebauthnOrigins,
      onLoginSuccess: uiSession
        ? (request, reply, input) => uiSession.onLoginSuccess(request, reply, input)
        : undefined,
      selfRegistrationEnabled: config.security.selfRegistrationEnabled,
      rateLimitConfig: config.security.rateLimit,
    });
  }

  // Agent proxy WebSocket route (for remote SSH agent clients)
  if (config.agentSocket.proxyEnabled && params.agentProxy && apiKeyRepo) {
    registerAgentProxyRoute({
      app,
      keyProvider: params.agentProxy.keyProvider,
      apiKeyRepo,
      accountRepo,
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
