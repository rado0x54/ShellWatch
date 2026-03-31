import { existsSync } from "node:fs";
import { resolve } from "node:path";
import fastifyCors from "@fastify/cors";
import fastifyStatic from "@fastify/static";
import fastifyWebsocket from "@fastify/websocket";
import Fastify from "fastify";
import { createServer as createViteServer } from "vite";
import type { Config } from "../config/index.js";
import type { ShellWatchDB } from "../db/connection.js";
import type { EndpointRepository } from "../db/repositories/endpoint-repo.js";
import type { SshKeyRepository } from "../db/repositories/key-repo.js";
import { registerMcpHttpTransport } from "../mcp/http-transport.js";
import type { TerminalManager } from "../terminal/index.js";
import type { KeyAvailability } from "../transport/key-directory-watcher.js";
import { registerWebAuthnRoutes } from "../webauthn/index.js";
import type { WsExtension } from "./ws-extension.js";
import { registerIpAllowlist } from "./ip-allowlist.js";
import { registerWebSocket } from "./ws-handler.js";

export interface AppOptions {
  logger?: boolean;
  skipVite?: boolean;
}

export async function buildApp(
  config: Config,
  terminalManager: TerminalManager,
  endpointRepo: EndpointRepository,
  keyRepo: SshKeyRepository,
  db: ShellWatchDB | null = null,
  wsExtensions: WsExtension[] = [],
  keyAvailability: KeyAvailability | null = null,
  options: AppOptions = {},
) {
  const app = Fastify({ logger: options.logger ?? true });
  const base = config.server.basePath;

  await app.register(fastifyCors, { origin: true });
  await app.register(fastifyWebsocket);

  registerIpAllowlist(app, config.security.allowedNetworks, [`${base}/mcp`]);

  // Redirect root to basePath when basePath is set
  if (base) {
    app.get("/", async (_request, reply) => {
      reply.redirect(`${base}/`);
    });
  }

  app.get(`${base}/health`, async () => ({ status: "ok" }));

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

  // --- Endpoint API ---

  app.get(`${base}/api/endpoints`, async () => {
    const all = await endpointRepo.findAll();
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
    try {
      await endpointRepo.create({ ...request.body, port: request.body.port ?? 22 });
      return { status: "created", id: request.body.id };
    } catch (err) {
      reply.status(400);
      return { error: (err as Error).message };
    }
  });

  app.put<{ Params: { id: string }; Body: Record<string, unknown> }>(
    `${base}/api/endpoints/:id`,
    async (request, reply) => {
      try {
        await endpointRepo.update(
          request.params.id,
          request.body as Parameters<EndpointRepository["update"]>[1],
        );
        return { status: "updated" };
      } catch (err) {
        reply.status(400);
        return { error: (err as Error).message };
      }
    },
  );

  app.delete<{ Params: { id: string } }>(`${base}/api/endpoints/:id`, async (request, reply) => {
    try {
      const activeSessions = terminalManager
        .listSessions()
        .filter((s) => s.endpointId === request.params.id);
      if (activeSessions.length > 0) {
        reply.status(409);
        return { error: "Cannot delete endpoint with active sessions" };
      }
      await endpointRepo.delete(request.params.id);
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

  // WebSocket for terminal I/O
  const wsHandler = registerWebSocket(app, terminalManager, base);
  for (const ext of wsExtensions) wsHandler.addExtension(ext);
  const { uiCreatedSessions } = wsHandler;

  // MCP server over streamable HTTP at /mcp
  await registerMcpHttpTransport(app, config, terminalManager, endpointRepo, keyRepo);

  // WebAuthn routes
  if (db) {
    registerWebAuthnRoutes(app, db, base, {
      hostHeader: config.server.trustedForwardedHostHeader,
      protoHeader: config.server.trustedForwardedProtoHeader,
    });
  }

  // Client runtime config
  app.get(`${base}/config.js`, async (_request, reply) => {
    reply.type("application/javascript");
    return `window.__BASE_PATH__=${JSON.stringify(base)};`;
  });

  // Serve client UI
  if (!options.skipVite) {
    const clientDist = resolve(import.meta.dirname, "../client");
    const hasBuiltClient = existsSync(resolve(clientDist, "index.html"));

    if (hasBuiltClient) {
      // Production: serve pre-built client assets
      await app.register(fastifyStatic, { root: clientDist, prefix: `${base}/` });
      app.setNotFoundHandler((_request, reply) => {
        reply.sendFile("index.html");
      });
    } else {
      // Development: Vite dev server with HMR
      const clientRoot = resolve(import.meta.dirname, "../../client");
      const vite = await createViteServer({
        root: clientRoot,
        server: {
          middlewareMode: true,
          hmr: { port: 24679 },
        },
        appType: "spa",
      });

      app.setNotFoundHandler((request, reply) => {
        // Strip basePath prefix so Vite sees root-relative paths
        if (base && request.raw.url?.startsWith(base)) {
          request.raw.url = request.raw.url.slice(base.length) || "/";
        }
        vite.middlewares.handle(request.raw, reply.raw, () => {
          reply.status(404).send({ error: "Not found" });
        });
      });
    }
  }

  return app;
}
