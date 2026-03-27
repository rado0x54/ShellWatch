import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { FastifyInstance } from "fastify";

export async function registerMcpHttpTransport(app: FastifyInstance, mcpServer: McpServer) {
  // Stateless mode — no MCP session management
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });

  await mcpServer.connect(transport);

  // Route all MCP traffic through /mcp using raw Node.js req/res
  app.all("/mcp", async (request, reply) => {
    const { raw: req, raw: _reqForBody } = request;
    const res = reply.raw;

    // Fastify already parsed the body for POST requests
    const parsedBody = request.method === "POST" ? request.body : undefined;

    await transport.handleRequest(req, res, parsedBody);

    // Tell Fastify we already handled the response
    reply.hijack();
  });

  return transport;
}
