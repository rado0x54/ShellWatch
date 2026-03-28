import { resolve } from "node:path";
import fastifyCors from "@fastify/cors";
import fastifyWebsocket from "@fastify/websocket";
import Fastify from "fastify";
import { createServer as createViteServer } from "vite";
import type { Config, Endpoint } from "../config/index.js";
import type { EndpointRepository } from "../db/repositories/endpoint-repo.js";
import { registerMcpHttpTransport } from "../mcp/http-transport.js";
import type { TerminalManager } from "../terminal/index.js";
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
  options: AppOptions = {},
) {
  const app = Fastify({ logger: options.logger ?? true });

  await app.register(fastifyCors, { origin: true });
  await app.register(fastifyWebsocket);

  registerIpAllowlist(app, config.security.allowedNetworks, ["/mcp"]);

  app.get("/health", async () => ({ status: "ok" }));

  // --- Endpoint API (backed by EndpointRepository) ---

  app.get("/api/endpoints", async () => {
    const all = await endpointRepo.findAll();
    return {
      endpoints: all.map(({ id, label, host, port, username }) => ({
        id,
        label,
        host,
        port,
        username,
      })),
    };
  });

  app.post<{ Body: Endpoint }>("/api/endpoints", async (request, reply) => {
    try {
      await endpointRepo.create(request.body);
      return { status: "created", id: request.body.id };
    } catch (err) {
      reply.status(400);
      return { error: (err as Error).message };
    }
  });

  app.put<{ Params: { id: string }; Body: Partial<Endpoint> }>(
    "/api/endpoints/:id",
    async (request, reply) => {
      try {
        await endpointRepo.update(request.params.id, request.body);
        return { status: "updated" };
      } catch (err) {
        reply.status(400);
        return { error: (err as Error).message };
      }
    },
  );

  app.delete<{ Params: { id: string } }>("/api/endpoints/:id", async (request, reply) => {
    try {
      // Reject if active sessions exist for this endpoint
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

  app.post<{ Body: { endpointId: string } }>("/api/sessions", async (request, reply) => {
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

  app.get("/api/sessions", async () => ({
    sessions: terminalManager.listSessions(),
  }));

  app.delete<{ Params: { sessionId: string } }>(
    "/api/sessions/:sessionId",
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
  const { uiCreatedSessions } = registerWebSocket(app, terminalManager);

  // MCP server over streamable HTTP at /mcp
  await registerMcpHttpTransport(app, config, terminalManager, endpointRepo);

  // Vite dev server
  if (!options.skipVite) {
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
      vite.middlewares.handle(request.raw, reply.raw, () => {
        reply.status(404).send({ error: "Not found" });
      });
    });
  }

  return app;
}
