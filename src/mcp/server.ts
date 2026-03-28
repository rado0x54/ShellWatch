import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AgentSession } from "../agent/index.js";
import { SUPPORTED_KEYS } from "../terminal/index.js";

export function createMcpServer(agentSession: AgentSession): McpServer {
  const endpoints = agentSession.listEndpoints();
  const endpointList = endpoints
    .map((s) => `- ${s.id}: ${s.label} (${s.username}@${s.host}:${s.port})`)
    .join("\n");

  const instructions = [
    "ShellWatch is an SSH session broker. You can create terminal sessions to remote servers, send commands, and read output.",
    "",
    "Available endpoints:",
    endpointList,
    "",
    "Workflow:",
    "1. Create a session with shellwatch_create_session (pick an endpoint ID from above)",
    '2. Send commands with shellwatch_send_keys (e.g., keys: ["text:ls -la", "enter"])',
    "3. Read the result with shellwatch_read_output (use afterOffset for incremental reads)",
    "4. Keep the session open for follow-up commands — do NOT close it after each command",
    "5. Only close with shellwatch_close_session when you are certain no more interactions are needed",
    "",
    "Session lifecycle:",
    "- Sessions are automatically closed when your MCP connection ends — you do not need to close them manually",
    "- Keep sessions open between commands so the human observer can see your work and send follow-ups",
    "- Creating a new session for every command is wasteful — reuse your existing session",
    "",
    "Notifications:",
    "- You will receive notifications/shellwatch/output_available when new output is ready (no need to poll)",
    "- You will receive notifications/shellwatch/session_status when your sessions change status",
  ].join("\n");

  const mcpServer = new McpServer({ name: "shellwatch", version: "0.4.0" }, { instructions });

  mcpServer.tool("shellwatch_list_endpoints", "List configured SSH endpoints", {}, async () => ({
    content: [{ type: "text", text: JSON.stringify({ endpoints }, null, 2) }],
  }));

  mcpServer.tool(
    "shellwatch_create_session",
    "Create a new terminal session for a configured endpoint",
    { endpointId: z.string().describe("ID of the endpoint to connect to") },
    async ({ endpointId }) => {
      try {
        const session = await agentSession.createSession(endpointId);
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
        return { isError: true, content: [{ type: "text", text: (err as Error).message }] };
      }
    },
  );

  mcpServer.tool("shellwatch_list_sessions", "List your active terminal sessions", {}, async () => {
    const sessions = agentSession.listSessions().map((s) => ({
      sessionId: s.sessionId,
      endpointId: s.endpointId,
      status: s.status,
      createdAt: s.createdAt.toISOString(),
    }));
    return {
      content: [{ type: "text", text: JSON.stringify({ sessions }, null, 2) }],
    };
  });

  mcpServer.tool(
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
        agentSession.sendKeys(sessionId, keys);
        return { content: [{ type: "text", text: JSON.stringify({ status: "sent", keys }) }] };
      } catch (err) {
        return { isError: true, content: [{ type: "text", text: (err as Error).message }] };
      }
    },
  );

  mcpServer.tool(
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
        const result = agentSession.readOutput(sessionId, afterOffset, limit);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return { isError: true, content: [{ type: "text", text: (err as Error).message }] };
      }
    },
  );

  mcpServer.tool(
    "shellwatch_close_session",
    "Close a terminal session and release resources",
    { sessionId: z.string().describe("ID of the session to close") },
    async ({ sessionId }) => {
      try {
        agentSession.closeSession(sessionId);
        return { content: [{ type: "text", text: JSON.stringify({ status: "closed" }) }] };
      } catch (err) {
        return { isError: true, content: [{ type: "text", text: (err as Error).message }] };
      }
    },
  );

  return mcpServer;
}
