import { randomUUID } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { FastifyInstance } from "fastify";
import type { Config } from "../config/index.js";
import type { TerminalManager } from "../terminal/index.js";
import { createMcpServer } from "./server.js";

export async function registerMcpHttpTransport(
  app: FastifyInstance,
  config: Config,
  terminalManager: TerminalManager,
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

      newTransport.onclose = () => {
        if (newTransport.sessionId) {
          transports.delete(newTransport.sessionId);
        }
      };

      newTransport.onerror = (err) => {
        app.log.error(err, "MCP transport error");
      };

      const mcpServer = createMcpServer(config, terminalManager);
      await mcpServer.connect(newTransport);

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

    // Store transport by session ID after first request
    if (transport.sessionId && !transports.has(transport.sessionId)) {
      transports.set(transport.sessionId, transport);
    }

    reply.hijack();
  });
}
