import { randomBytes, randomUUID } from "node:crypto";
import { resolve } from "node:path";
import fastifyCors from "@fastify/cors";
import fastifyStatic from "@fastify/static";
import fastifyWebsocket from "@fastify/websocket";
import Fastify from "fastify";
import type { Config } from "../config/index.js";
import { eq } from "drizzle-orm";
import type { ShellWatchDB } from "../db/connection.js";
import {
  accounts as accountsTable,
  apiKeys as apiKeysTable,
  endpointKeys,
  endpoints as endpointsTable,
  sessionHistory,
  webauthnCredentials,
} from "../db/schema.js";
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

  app.put<{ Body: { name?: string } }>(`${base}/api/auth/me`, async (request, reply) => {
    const accountId = request.accountId;
    if (!accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    const { name } = request.body;
    if (name !== undefined) {
      const trimmed = name.trim();
      if (!trimmed) {
        reply.status(400);
        return { error: "Name cannot be empty" };
      }
      await accountRepo.update(accountId, { name: trimmed });
    }
    return { status: "updated" };
  });

  // --- Account Management (admin only) ---

  app.get(`${base}/api/accounts`, async (request, reply) => {
    if (!request.accountId || !accountRepo.isAdmin(request.accountId)) {
      reply.status(403);
      return { error: "Admin access required" };
    }
    const all = await accountRepo.findAll();
    return {
      accounts: all.map((a) => ({
        id: a.id,
        name: a.name,
        type: a.type,
        isAdmin: a.isAdmin,
        enabled: a.enabled,
        maxSessions: a.maxSessions,
        lastUsedAt: a.lastUsedAt,
        createdAt: a.createdAt,
      })),
    };
  });

  app.delete<{ Params: { id: string } }>(`${base}/api/accounts/:id`, async (request, reply) => {
    if (!request.accountId || !accountRepo.isAdmin(request.accountId)) {
      reply.status(403);
      return { error: "Admin access required" };
    }
    const targetId = request.params.id;

    // Cannot delete yourself
    if (targetId === request.accountId) {
      reply.status(400);
      return { error: "Cannot delete your own account" };
    }

    // Cannot delete the admin account
    if (accountRepo.isAdmin(targetId)) {
      reply.status(400);
      return { error: "Cannot delete the admin account" };
    }

    // Hard-delete: cascade all owned data (order matters for FK constraints)
    if (db) {
      // Get the account's endpoint IDs for junction table cleanup
      const accountEndpoints = db
        .select({ id: endpointsTable.id })
        .from(endpointsTable)
        .where(eq(endpointsTable.accountId, targetId))
        .all();
      for (const ep of accountEndpoints) {
        db.delete(endpointKeys).where(eq(endpointKeys.endpointId, ep.id)).run();
      }
      db.delete(sessionHistory).where(eq(sessionHistory.accountId, targetId)).run();
      db.delete(webauthnCredentials).where(eq(webauthnCredentials.accountId, targetId)).run();
      db.delete(apiKeysTable).where(eq(apiKeysTable.accountId, targetId)).run();
      db.delete(endpointsTable).where(eq(endpointsTable.accountId, targetId)).run();
      db.delete(accountsTable).where(eq(accountsTable.id, targetId)).run();
    }

    return { status: "deleted" };
  });

  // --- SSH Keys API ---

  app.get(`${base}/api/keys`, async (request) => {
    const allKeys = await keyRepo.findAll();
    const isAdmin = request.accountId ? accountRepo.isAdmin(request.accountId) : false;

    // File-based keys: admin only
    const fileKeys = isAdmin ? allKeys.filter((k) => k.type === "file") : [];

    // Webauthn SSH keys: scoped to account (look up which credentials belong to this account)
    let webauthnKeys: typeof allKeys = [];
    if (request.accountId) {
      const accountCredIds = new Set(
        db
          ? db
              .select({ id: webauthnCredentials.id })
              .from(webauthnCredentials)
              .where(eq(webauthnCredentials.accountId, request.accountId))
              .all()
              .map((c) => c.id)
          : [],
      );
      webauthnKeys = allKeys.filter((k) => k.type === "webauthn" && accountCredIds.has(k.id));
    }

    const visibleKeys = [...webauthnKeys, ...fileKeys];
    return {
      keys: visibleKeys.map((k) => {
        const available =
          k.type === "webauthn" || (keyAvailability?.isAvailable(k.fingerprint) ?? true);
        return {
          id: k.id,
          label: k.label,
          type: k.type,
          algorithm: k.publicKey.split(" ")[0] ?? "unknown",
          fingerprint: k.fingerprint,
          revoked: !k.enabled,
          available: k.enabled && available,
          authorizedKeysEntry: k.publicKey ? `${k.publicKey}` : null,
          createdAt: k.createdAt,
          lastUsedAt: null, // TODO: track properly via #28
        };
      }),
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
      label: string;
      host: string;
      port?: number;
      username?: string;
      keyId?: string;
    };
  }>(`${base}/api/endpoints`, async (request, reply) => {
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    try {
      const id = randomUUID();
      await endpointRepo.create({
        id,
        accountId: request.accountId,
        label: request.body.label,
        host: request.body.host,
        port: request.body.port ?? 22,
        username: request.body.username ?? "shellwatch",
        keyId: request.body.keyId,
      });
      return { status: "created", id };
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
    if (!request.accountId) {
      reply.status(401);
      return { error: "Not authenticated" };
    }
    try {
      // Enforce per-account session limit (scoped to this account's endpoints)
      const account = await accountRepo.findById(request.accountId);
      if (account) {
        const accountEndpoints = await endpointRepo.findAllForAccount(request.accountId);
        const accountEndpointIds = new Set(accountEndpoints.map((e) => e.id));
        const activeSessions = terminalManager.listSessions();
        const accountSessions = activeSessions.filter(
          (s) => accountEndpointIds.has(s.endpointId) && s.status === "open",
        );
        if (accountSessions.length >= account.maxSessions) {
          reply.status(429);
          return {
            error: `Maximum concurrent sessions (${account.maxSessions}) reached`,
          };
        }
      }

      const { endpointId } = request.body;
      const endpoint = await endpointRepo.findByIdForAccount(endpointId, request.accountId);
      if (!endpoint) {
        reply.status(404);
        return { error: "Endpoint not found" };
      }
      const session = await terminalManager.create(endpointId, "ui");
      uiCreatedSessions.add(session.sessionId);

      // Update lastUsedAt on the assigned passkey (if it's a webauthn key)
      if (endpoint.keyId && db) {
        db.update(webauthnCredentials)
          .set({ lastUsedAt: new Date().toISOString() })
          .where(eq(webauthnCredentials.id, endpoint.keyId))
          .run();
      }

      return session;
    } catch (err) {
      reply.status(400);
      return { error: (err as Error).message };
    }
  });

  app.get(`${base}/api/sessions`, async (request) => {
    if (!request.accountId) return { sessions: [] };
    // Only show sessions on endpoints owned by this account
    const accountEndpoints = await endpointRepo.findAllForAccount(request.accountId);
    const endpointIds = new Set(accountEndpoints.map((e) => e.id));
    const sessions = terminalManager.listSessions().filter((s) => endpointIds.has(s.endpointId));
    return { sessions };
  });

  app.delete<{ Params: { sessionId: string } }>(
    `${base}/api/sessions/:sessionId`,
    async (request, reply) => {
      if (!request.accountId) {
        reply.status(401);
        return { error: "Not authenticated" };
      }
      const session = terminalManager.getSession(request.params.sessionId);
      if (!session) {
        reply.status(404);
        return { error: "Session not found" };
      }
      // Verify the session's endpoint belongs to this account
      const endpoint = await endpointRepo.findByIdForAccount(session.endpointId, request.accountId);
      if (!endpoint) {
        reply.status(403);
        return { error: "Access denied" };
      }
      terminalManager.close(request.params.sessionId);
      return { status: "closed" };
    },
  );

  // --- API Keys (scoped to account) ---

  if (apiKeyRepo) {
    app.get(`${base}/api/keys/api`, async (request) => {
      if (!request.accountId) return { keys: [] };
      const keys = await apiKeyRepo.findAll();
      return {
        keys: keys
          .filter((k) => k.accountId === request.accountId)
          .map((k) => ({
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
      if (!request.accountId) {
        reply.status(401);
        return { error: "Not authenticated" };
      }
      const { label } = request.body;
      if (!label) {
        reply.status(400);
        return { error: "Label is required" };
      }
      const raw = `sw_${randomBytes(24).toString("hex")}`;
      const keyHash = hashApiKey(raw);
      const keyPrefix = raw.slice(0, 10);
      const id = randomUUID();
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

    app.delete<{ Params: { id: string } }>(`${base}/api/keys/api/:id`, async (request, reply) => {
      if (!request.accountId) {
        reply.status(401);
        return { error: "Not authenticated" };
      }
      // Verify ownership before revoking
      const keys = await apiKeyRepo.findAll();
      const key = keys.find((k) => k.id === request.params.id && k.accountId === request.accountId);
      if (!key) {
        reply.status(404);
        return { error: "API key not found" };
      }
      await apiKeyRepo.revoke(request.params.id);
      return { status: "revoked" };
    });
  }

  // WebSocket for terminal I/O
  const wsHandler = registerWebSocket(app, terminalManager, base);
  for (const ext of wsExtensions) wsHandler.addExtension(ext);
  const { uiCreatedSessions } = wsHandler;

  // MCP server over streamable HTTP at /mcp
  await registerMcpHttpTransport(app, config, terminalManager, endpointRepo, keyRepo, accountRepo);

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
