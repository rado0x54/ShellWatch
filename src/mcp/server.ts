import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Config } from "../config/index.js";
import { SUPPORTED_KEYS, type TerminalManager } from "../terminal/index.js";

export function createMcpServer(config: Config, terminalManager: TerminalManager): McpServer {
  const server = new McpServer({
    name: "shellwatch",
    version: "0.2.0",
  });

  server.tool("shellwatch_list_endpoints", "List configured SSH endpoints", {}, async () => {
    const endpoints = config.servers.map(({ id, label, host, port, username }) => ({
      id,
      label,
      host,
      port,
      username,
    }));
    return {
      content: [{ type: "text", text: JSON.stringify({ endpoints }, null, 2) }],
    };
  });

  server.tool(
    "shellwatch_create_session",
    "Create a new terminal session for a configured endpoint",
    {
      endpointId: z.string().describe("ID of the endpoint to connect to"),
    },
    async ({ endpointId }) => {
      try {
        const session = await terminalManager.create(endpointId, "mcp");
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  sessionId: session.sessionId,
                  endpointId: session.endpointId,
                  status: session.status,
                },
                null,
                2,
              ),
            },
          ],
        };
      } catch (err) {
        return {
          isError: true,
          content: [{ type: "text", text: (err as Error).message }],
        };
      }
    },
  );

  server.tool("shellwatch_list_sessions", "List all active terminal sessions", {}, async () => {
    const sessions = terminalManager.listSessions().map((s) => ({
      sessionId: s.sessionId,
      endpointId: s.endpointId,
      status: s.status,
      createdAt: s.createdAt.toISOString(),
      source: s.source,
    }));
    return {
      content: [{ type: "text", text: JSON.stringify({ sessions }, null, 2) }],
    };
  });

  server.tool(
    "shellwatch_exec",
    [
      "Execute a shell command and return the result when complete.",
      "This is the primary tool for running commands. Returns output and exit code.",
      "For interactive programs (vim, top), use shellwatch_send_keys instead.",
    ].join(" "),
    {
      sessionId: z.string().describe("ID of the session"),
      command: z.string().describe("Shell command to execute"),
      timeout: z
        .number()
        .optional()
        .default(30000)
        .describe("Timeout in milliseconds (default: 30000)"),
    },
    async ({ sessionId, command, timeout }) => {
      try {
        const result = await terminalManager.exec(sessionId, command, timeout);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  output: result.output,
                  exitCode: result.exitCode,
                  durationMs: result.durationMs,
                  timedOut: result.timedOut,
                },
                null,
                2,
              ),
            },
          ],
        };
      } catch (err) {
        return {
          isError: true,
          content: [{ type: "text", text: (err as Error).message }],
        };
      }
    },
  );

  server.tool(
    "shellwatch_send_keys",
    [
      "Send named keystrokes or control sequences to a terminal session.",
      `Supported keys: ${SUPPORTED_KEYS.join(", ")}.`,
      'Use "text:<raw>" for arbitrary text (e.g., "text:hello\\n").',
      'Supports sequences: ["ctrl+c", "enter"] sends Ctrl+C then Enter.',
    ].join(" "),
    {
      sessionId: z.string().describe("ID of the session"),
      keys: z.array(z.string()).describe("Array of key names to send"),
    },
    async ({ sessionId, keys }) => {
      try {
        terminalManager.sendKeys(sessionId, keys);
        return {
          content: [{ type: "text", text: JSON.stringify({ status: "sent", keys }) }],
        };
      } catch (err) {
        return {
          isError: true,
          content: [{ type: "text", text: (err as Error).message }],
        };
      }
    },
  );

  server.tool(
    "shellwatch_close_session",
    "Close a terminal session and release resources",
    {
      sessionId: z.string().describe("ID of the session to close"),
    },
    async ({ sessionId }) => {
      try {
        terminalManager.close(sessionId);
        return {
          content: [{ type: "text", text: JSON.stringify({ status: "closed" }) }],
        };
      } catch (err) {
        return {
          isError: true,
          content: [{ type: "text", text: (err as Error).message }],
        };
      }
    },
  );

  return server;
}
