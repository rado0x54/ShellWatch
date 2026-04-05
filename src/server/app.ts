import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import fastifyCors from "@fastify/cors";
import fastifyStatic from "@fastify/static";
import fastifyWebsocket from "@fastify/websocket";
import Fastify from "fastify";
import type { Config } from "../config/index.js";
import type { ShellWatchDB } from "../db/connection.js";
import type {
  AccountRepository,
  ApiKeyRepository,
  EndpointRepository,
  SshKeyRepository,
} from "../db/index.js";
import { registerAgentProxyRoute } from "../agent-socket/index.js";
import { registerMcpHttpTransport } from "../mcp/http-transport.js";
import type { TerminalManager } from "../terminal/index.js";
import type { KeyAvailability, PrivateKeyProvider } from "../transport/key-directory-watcher.js";
import type { ScannedKey } from "../transport/key-scanner.js";
import { hasPasskeys as hasPasskeysQuery } from "../db/repositories/credential-queries.js";
import { registerWebAuthnRoutes } from "../webauthn/index.js";
import { registerApiKeyAuth } from "./auth/api-key-auth.js";
import { registerAuthGate } from "./auth/auth-gate.js";
import { registerIpAllowlist } from "./auth/ip-allowlist.js";
import { registerAccountRoutes } from "./routes/accounts.js";
import { registerApiKeyRoutes } from "./routes/api-keys.js";
import { registerEndpointRoutes } from "./routes/endpoints.js";
import { registerSessionRoutes } from "./routes/sessions.js";
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
  apiKeyRepo?: ApiKeyRepository | null;
  options?: AppOptions;
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

  const app = Fastify({ logger: options.logger ?? true });
  const base = config.server.basePath;

  // Cookie secret for session signing
  const cookieSecret = config.security.cookieSecret ?? randomBytes(32).toString("hex");
  if (!config.security.cookieSecret) {
    app.log.warn("No cookieSecret in config — sessions will not survive server restarts");
  }

  await app.register(fastifyCors, { origin: true });
  await app.register(fastifyWebsocket);

  // Decorate request with accountId (set by auth gate / API key auth)
  app.decorateRequest("accountId", null);

  // Auth gate: onboarding + login enforcement
  registerAuthGate({
    app,
    basePath: base,
    secret: cookieSecret,
    accountRepo,
    checkHasPasskeys: db ? () => hasPasskeysQuery(db) : () => true,
  });

  // IP allowlist + API key auth for MCP
  registerIpAllowlist(app, config.security.allowedNetworks, [`${base}/mcp`]);
  if (apiKeyRepo) {
    registerApiKeyAuth(app, apiKeyRepo, `${base}/mcp`, accountRepo);
  }

  // Redirect root to basePath when basePath is set
  if (base) {
    app.get("/", async (_request, reply) => {
      reply.redirect(`${base}/`);
    });
  }

  app.get(`${base}/health`, async () => ({ status: "ok" }));

  // --- REST API routes ---
  registerAccountRoutes({ app, basePath: base, accountRepo, db });
  registerSshKeyRoutes({ app, basePath: base, keyRepo, accountRepo, keyAvailability });
  registerEndpointRoutes({ app, basePath: base, endpointRepo, accountRepo, terminalManager });

  // WebSocket for terminal I/O (must register before session routes for uiCreatedSessions)
  const wsHandler = registerWebSocket(app, terminalManager, base);
  for (const ext of wsExtensions) wsHandler.addExtension(ext);
  const { uiCreatedSessions } = wsHandler;

  registerSessionRoutes({
    app,
    basePath: base,
    endpointRepo,
    accountRepo,
    terminalManager,
    uiCreatedSessions,
    db,
  });

  if (apiKeyRepo) {
    registerApiKeyRoutes({ app, basePath: base, apiKeyRepo, accountRepo });
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
      basePath: base,
      sessionConfig: { secret: cookieSecret, ttlSeconds: config.security.sessionTtlSeconds },
    });
  }

  // Agent proxy WebSocket route (for remote SSH agent clients)
  if (config.agentSocket.proxyEnabled && params.agentProxy && apiKeyRepo) {
    registerAgentProxyRoute({
      app,
      basePath: base,
      keyProvider: params.agentProxy.keyProvider,
      apiKeyRepo,
      accountRepo,
      signingBridge: params.agentProxy.signingBridge,
      findCredentialsForAccount: params.agentProxy.findCredentialsForAccount,
      rpId: params.agentProxy.rpId,
    });
    app.log.info(`Agent proxy endpoint enabled at ${base}/agent-proxy`);
  }

  // Client runtime config
  app.get(`${base}/config.js`, async (_request, reply) => {
    reply.type("application/javascript");
    return `window.__BASE_PATH__=${JSON.stringify(base)};`;
  });

  // Static client files (built by SvelteKit adapter-static -> dist/client/)
  if (!options.skipStaticFiles) {
    const clientDist = resolve(process.cwd(), "dist/client");
    await app.register(fastifyStatic, { root: clientDist, prefix: `${base}/` });

    // SPA fallback: serve index.html for client-side routing
    app.setNotFoundHandler((_request, reply) => {
      reply.sendFile("index.html");
    });
  }

  return app;
}
