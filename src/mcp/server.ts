import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Config } from "../config/index.js";
import { SUPPORTED_KEYS, type TerminalManager } from "../terminal/index.js";

export function createMcpServer(config: Config, terminalManager: TerminalManager): McpServer {
  const server = new McpServer({
    name: "shellwatch",
    version: "0.3.0",
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
    "shellwatch_send_keys",
    [
      "Send named keystrokes or text to a terminal session.",
      "This is how you type commands and interact with the shell.",
      'To run a command: send_keys(["text:ls -la", "enter"]), then read_output to see the result.',
      `Supported keys: ${SUPPORTED_KEYS.join(", ")}.`,
      'Use "text:<content>" for arbitrary text (e.g., "text:ls -la").',
      'Supports sequences: ["text:ls -la", "enter"] types the command and presses Enter.',
    ].join(" "),
    {
      sessionId: z.string().describe("ID of the session"),
      keys: z.array(z.string()).describe("Array of key names to send in sequence"),
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
    "shellwatch_read_output",
    [
      "Read terminal output from a session.",
      "Returns buffered output with an offset for incremental reads.",
      "After sending a command with send_keys, wait briefly then call read_output to see the result.",
      "Use afterOffset from the previous read to get only new output since your last read.",
    ].join(" "),
    {
      sessionId: z.string().describe("ID of the session"),
      afterOffset: z
        .number()
        .optional()
        .describe("Read output after this offset (from a previous read)"),
      limit: z.number().optional().describe("Maximum characters to return (default: 4000)"),
    },
    async ({ sessionId, afterOffset, limit }) => {
      try {
        const result = terminalManager.readOutput(sessionId, afterOffset, limit);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
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
