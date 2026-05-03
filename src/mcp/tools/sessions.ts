// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AgentSession } from "../../agent/index.js";
import { SUPPORTED_KEYS } from "../../terminal/index.js";

export function registerSessionTools(mcpServer: McpServer, agentSession: AgentSession) {
  mcpServer.tool(
    "shellwatch_create_session",
    [
      "Create a new terminal session for a configured endpoint.",
      "The `reason` parameter is required and shown to the human approver in the",
      "passkey-tap UI — explain the user-visible intent (e.g. 'investigate disk",
      "alert on web-01', 'deploy hotfix for incident #42'), not implementation",
      "detail. Vague reasons like 'check things' will be rejected by approvers.",
    ].join(" "),
    {
      endpointId: z.string().describe("ID of the endpoint to connect to"),
      reason: z
        .string()
        .max(500)
        .transform((s) => s.trim())
        .refine((s) => s.length > 0, { message: "reason must not be empty" })
        .describe("Why this session is being created. Shown to the human approver — be specific."),
    },
    async ({ endpointId, reason }) => {
      try {
        const session = await agentSession.createSession(endpointId, reason);
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
    return { content: [{ type: "text", text: JSON.stringify({ sessions }, null, 2) }] };
  });

  mcpServer.tool(
    "shellwatch_send_keys",
    [
      "Send named keystrokes or text to a terminal session.",
      'To run a command: send_keys(["text:ls -la", "enter"]), then read_output to see the result.',
      `Supported keys: ${SUPPORTED_KEYS.join(", ")}.`,
      'Use "text:<content>" for arbitrary text.',
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
    "Read terminal output from a session. Use afterOffset for incremental reads.",
    {
      sessionId: z.string().describe("ID of the session"),
      afterOffset: z.number().optional().describe("Read output after this offset"),
      limit: z.number().optional().describe("Max characters to return (default: 4000)"),
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
}
