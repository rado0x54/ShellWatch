import { randomBytes, randomUUID } from "node:crypto";
import { resolve } from "node:path";
import fastifyCors from "@fastify/cors";
import fastifyStatic from "@fastify/static";
import fastifyWebsocket from "@fastify/websocket";
import Fastify from "fastify";
import type { Config } from "../config/index.js";
import type { ShellWatchDB } from "../db/connection.js";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { ApiKeyRepository } from "../db/repositories/api-key-repo.js";
import type { EndpointRepository } from "../db/repositories/endpoint-repo.js";
import type { SshKeyRepository } from "../db/repositories/key-repo.js";
import { registerMcpHttpTransport } from "../mcp/http-transport.js";
import type { TerminalManager } from "../terminal/index.js";
import type { KeyAvailability } from "../transport/key-directory-watcher.js";
import { hasPasskeys as hasPasskeysQuery } from "../db/repositories/credential-queries.js";
import { registerWebAuthnRoutes } from "../webauthn/index.js";
import { hashApiKey, registerApiKeyAuth } from "./auth/api-key-auth.js";
import { registerAuthGate } from "./auth/auth-gate.js";
import { registerIpAllowlist } from "./auth/ip-allowlist.js";
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

  // --- Auth: current account ---
  app.get(`${base}/api/auth/me`, async (request, reply) => {
    const accountId = request.accountId;
    if (!accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    const account = await accountRepo.findById(accountId);
    if (!account) {
      reply.status(401);
      return { error: "Account not found" };
    }
    return {
      id: account.id,
      name: account.name,
      type: account.type,
      isAdmin: account.isAdmin,
    };
  });

  // --- SSH Keys API ---

  app.get(`${base}/api/keys`, async () => {
    const allKeys = await keyRepo.findAll();
    return {
      keys: allKeys.map((k) => ({
        id: k.id,
        label: k.label,
        type: k.type,
        fingerprint: k.fingerprint,
        available: k.type === "webauthn" || (keyAvailability?.isAvailable(k.fingerprint) ?? true),
        authorizedKeysEntry: k.publicKey ? `${k.publicKey}` : null,
      })),
    };
  });

  // --- Endpoint API (scoped to account) ---

  app.get(`${base}/api/endpoints`, async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    const all = await endpointRepo.findAllForAccount(request.accountId);
    return {
      endpoints: all.map(({ id, label, host, port, username, keyId }) => ({
        id,
        label,
        host,
        port,
        username,
        keyId,
      })),
    };
  });

  app.post<{
    Body: {
      id: string;
      label: string;
      host: string;
      port?: number;
      username: string;
      keyId?: string;
    };
  }>(`${base}/api/endpoints`, async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    try {
      await endpointRepo.create({
        ...request.body,
        accountId: request.accountId,
        port: request.body.port ?? 22,
      });
      return { status: "created", id: request.body.id };
    } catch (err) {
      reply.status(400);
      return { error: (err as Error).message };
    }
  });

  app.put<{ Params: { id: string }; Body: Record<string, unknown> }>(
    `${base}/api/endpoints/:id`,
    async (request, reply) => {
      if (!request.accountId) {
        reply.status(401);
        return { error: "Not authenticated" };
      }
      try {
        await endpointRepo.update(
          request.params.id,
          request.accountId,
          request.body as Parameters<EndpointRepository["update"]>[2],
        );
        return { status: "updated" };
      } catch (err) {
        reply.status(400);
        return { error: (err as Error).message };
      }
    },
  );

  app.delete<{ Params: { id: string } }>(`${base}/api/endpoints/:id`, async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    try {
      const activeSessions = terminalManager
        .listSessions()
        .filter((s) => s.endpointId === request.params.id);
      if (activeSessions.length > 0) {
        reply.status(409);
        return { error: "Cannot delete endpoint with active sessions" };
      }
      await endpointRepo.delete(request.params.id, request.accountId);
      return { status: "deleted" };
    } catch (err) {
      reply.status(400);
      return { error: (err as Error).message };
    }
  });

  // --- Session API ---

  app.post<{ Body: { endpointId: string } }>(`${base}/api/sessions`, async (request, reply) => {
    try {
      const { endpointId } = request.body;
      const session = await terminalManager.create(endpointId, "ui");
      uiCreatedSessions.add(session.sessionId);
      return session;
    } catch (err) {
      reply.status(400);
      return { error: (err as Error).message };
    }
  });

  app.get(`${base}/api/sessions`, async () => ({
    sessions: terminalManager.listSessions(),
  }));

  app.delete<{ Params: { sessionId: string } }>(
    `${base}/api/sessions/:sessionId`,
    async (request, reply) => {
      try {
        terminalManager.close(request.params.sessionId);
        return { status: "closed" };
      } catch (err) {
        reply.status(404);
        return { error: (err as Error).message };
      }
    },
  );

  // --- API Keys ---

  if (apiKeyRepo) {
    app.get(`${base}/api/keys/api`, async () => {
      const keys = await apiKeyRepo.findAll();
      return {
        keys: keys.map((k) => ({
          id: k.id,
          label: k.label,
          keyPrefix: k.keyPrefix,
          scopes: k.scopes,
          enabled: k.enabled,
          createdAt: k.createdAt,
        })),
      };
    });

    app.post<{ Body: { label: string } }>(`${base}/api/keys/api`, async (request, reply) => {
      const { label } = request.body;
      if (!label) {
        reply.status(400);
        return { error: "Label is required" };
      }
      const raw = `sw_${randomBytes(24).toString("hex")}`;
      const keyHash = hashApiKey(raw);
      const keyPrefix = raw.slice(0, 10);
      const id = randomUUID();
      if (!request.accountId) {
        reply.status(401);
        return { error: "Not authenticated" };
      }
      await apiKeyRepo.create({
        id,
        accountId: request.accountId,
        label,
        keyHash,
        keyPrefix,
        scopes: ["mcp"],
      });
      return { id, label, keyPrefix, key: raw };
    });

    app.delete<{ Params: { id: string } }>(`${base}/api/keys/api/:id`, async (request) => {
      await apiKeyRepo.revoke(request.params.id);
      return { status: "revoked" };
    });
  }

  // WebSocket for terminal I/O
  const wsHandler = registerWebSocket(app, terminalManager, base);
  for (const ext of wsExtensions) wsHandler.addExtension(ext);
  const { uiCreatedSessions } = wsHandler;

  // MCP server over streamable HTTP at /mcp
  await registerMcpHttpTransport(app, config, terminalManager, endpointRepo, keyRepo);

  // WebAuthn routes
  if (db) {
    registerWebAuthnRoutes({
      app,
      db,
      accountRepo,
      basePath: base,
      proxy: {
        hostHeader: config.server.trustedForwardedHostHeader,
        protoHeader: config.server.trustedForwardedProtoHeader,
      },
      sessionConfig: { secret: cookieSecret, ttlSeconds: config.security.sessionTtlSeconds },
      trustedOrigins: config.security.trustedWebauthnOrigins,
    });
  }

  // Client runtime config
  app.get(`${base}/config.js`, async (_request, reply) => {
    reply.type("application/javascript");
    return `window.__BASE_PATH__=${JSON.stringify(base)};`;
  });

  // Static client files (built by SvelteKit adapter-static → dist/client/)
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
