import { randomUUID } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { FastifyInstance } from "fastify";
import { AgentSession } from "../agent/index.js";
import type { Config } from "../config/index.js";
import type { EndpointRepository } from "../db/repositories/endpoint-repo.js";
import type { TerminalManager } from "../terminal/index.js";
import { attachMcpNotifications } from "./notifications.js";
import { createMcpServer } from "./server.js";

export async function registerMcpHttpTransport(
  app: FastifyInstance,
  config: Config,
  terminalManager: TerminalManager,
  endpointRepo: EndpointRepository,
) {
  const transports = new Map<string, StreamableHTTPServerTransport>();

  app.addHook("onRequest", async (request, reply) => {
    if (request.url !== "/mcp") return;

    const sessionId = request.headers["mcp-session-id"] as string | undefined;
    let transport = sessionId ? transports.get(sessionId) : undefined;

    if (!transport) {
      const newTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });

      const agentSession = new AgentSession(endpointRepo, terminalManager, "mcp");
      const mcpServer = await createMcpServer(agentSession);

      await mcpServer.connect(newTransport);

      const notifications = attachMcpNotifications(mcpServer, terminalManager, agentSession, {
        debounceMs: config.notifications.mcp.debounceMs,
      });

      newTransport.onclose = () => {
        if (newTransport.sessionId) {
          transports.delete(newTransport.sessionId);
        }
        agentSession.destroy();
        notifications.destroy();
      };

      newTransport.onerror = (err) => {
        app.log.error(err, "MCP transport error");
      };

      transport = newTransport;
    }

    try {
      await transport.handleRequest(request.raw, reply.raw);
    } catch (err) {
      app.log.error(err, "MCP handleRequest error");
      if (!reply.raw.headersSent) {
        reply.raw.writeHead(500, { "Content-Type": "application/json" });
        reply.raw.end(
          JSON.stringify({
            jsonrpc: "2.0",
            error: { code: -32603, message: (err as Error).message },
            id: null,
          }),
        );
      }
    }

    if (transport.sessionId && !transports.has(transport.sessionId)) {
      transports.set(transport.sessionId, transport);
    }

    reply.hijack();
  });
}
