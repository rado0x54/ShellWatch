import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AgentSession } from "../agent/index.js";
import type { EndpointRepository } from "../db/repositories/endpoint-repo.js";
import type { SshKeyRepository } from "../db/repositories/key-repo.js";
import { SUPPORTED_KEYS } from "../terminal/index.js";

export async function createMcpServer(
  agentSession: AgentSession,
  endpointRepo: EndpointRepository,
  keyRepo: SshKeyRepository,
  accountId?: string | null,
): Promise<McpServer> {
  const endpoints = await agentSession.listEndpoints();
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

  const mcpServer = new McpServer({ name: "shellwatch", version: "0.5.0" }, { instructions });

  // --- Session tools ---

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

  // --- Manage Endpoints ---

  mcpServer.tool(
    "shellwatch_manage_endpoints",
    "Manage SSH endpoints. Actions: list, read, create, update, delete.",
    {
      action: z.enum(["list", "read", "create", "update", "delete"]).describe("Action to perform"),
      id: z.string().optional().describe("Endpoint ID (required for read, update, delete)"),
      data: z
        .object({
          label: z.string().optional(),
          host: z.string().optional(),
          port: z.number().optional(),
          username: z.string().optional(),
          keyId: z.string().optional().describe("File-based SSH key ID"),
          passkeyId: z
            .string()
            .optional()
            .describe("WebAuthn passkey ID (mutually exclusive with keyId)"),
        })
        .optional()
        .describe("Endpoint data (for create and update)"),
    },
    async ({ action, id, data }) => {
      try {
        switch (action) {
          case "list": {
            if (!accountId) {
              return {
                isError: true,
                content: [{ type: "text", text: "No account context" }],
              };
            }
            const all = await endpointRepo.findAllForAccount(accountId);
            const result = all.map(({ id, label, host, port, username, keyId, passkeyId }) => ({
              id,
              label,
              host,
              port,
              username,
              keyId,
              passkeyId,
            }));
            return {
              content: [{ type: "text", text: JSON.stringify({ endpoints: result }, null, 2) }],
            };
          }
          case "read": {
            if (!id) return { isError: true, content: [{ type: "text", text: "id is required" }] };
            if (!accountId) {
              return {
                isError: true,
                content: [{ type: "text", text: "No account context" }],
              };
            }
            const ep = await endpointRepo.findByIdForAccount(id, accountId);
            if (!ep)
              return {
                isError: true,
                content: [{ type: "text", text: `Endpoint not found: ${id}` }],
              };
            const safe = ep;
            return { content: [{ type: "text", text: JSON.stringify(safe, null, 2) }] };
          }
          case "create": {
            if (!id || !data?.label || !data?.host || !data?.username) {
              return {
                isError: true,
                content: [
                  { type: "text", text: "id, data.label, data.host, data.username are required" },
                ],
              };
            }
            if (!accountId) {
              return {
                isError: true,
                content: [{ type: "text", text: "No account context for endpoint creation" }],
              };
            }
            await endpointRepo.create({
              id,
              accountId,
              label: data.label,
              host: data.host,
              port: data.port ?? 22,
              username: data.username,
              keyId: data.keyId,
              passkeyId: data.passkeyId,
            });
            return { content: [{ type: "text", text: JSON.stringify({ status: "created", id }) }] };
          }
          case "update": {
            if (!id || !data)
              return {
                isError: true,
                content: [{ type: "text", text: "id and data are required" }],
              };
            if (accountId) {
              await endpointRepo.update(id, accountId, data);
            } else {
              return {
                isError: true,
                content: [{ type: "text", text: "No account context for endpoint update" }],
              };
            }
            return { content: [{ type: "text", text: JSON.stringify({ status: "updated", id }) }] };
          }
          case "delete": {
            if (!id) return { isError: true, content: [{ type: "text", text: "id is required" }] };
            if (accountId) {
              await endpointRepo.delete(id, accountId);
            } else {
              return {
                isError: true,
                content: [{ type: "text", text: "No account context for endpoint deletion" }],
              };
            }
            return { content: [{ type: "text", text: JSON.stringify({ status: "deleted", id }) }] };
          }
        }
      } catch (err) {
        return { isError: true, content: [{ type: "text", text: (err as Error).message }] };
      }
    },
  );

  // --- Manage SSH Keys ---

  mcpServer.tool(
    "shellwatch_manage_keys",
    "Manage SSH keys. Keys are auto-discovered from the key directory. Actions: list, read.",
    {
      action: z.enum(["list", "read"]).describe("Action to perform"),
      id: z.string().optional().describe("Key ID (required for read)"),
    },
    async ({ action, id }) => {
      try {
        switch (action) {
          case "list": {
            const all = await keyRepo.findAll();
            const result = all.map(({ id, label, type, fingerprint }) => ({
              id,
              label,
              type,
              fingerprint,
            }));
            return { content: [{ type: "text", text: JSON.stringify({ keys: result }, null, 2) }] };
          }
          case "read": {
            if (!id) return { isError: true, content: [{ type: "text", text: "id is required" }] };
            const key = await keyRepo.findById(id);
            if (!key)
              return { isError: true, content: [{ type: "text", text: `Key not found: ${id}` }] };
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(
                    {
                      id: key.id,
                      label: key.label,
                      type: key.type,
                      fingerprint: key.fingerprint,
                      publicKey: key.publicKey,
                    },
                    null,
                    2,
                  ),
                },
              ],
            };
          }
        }
      } catch (err) {
        return { isError: true, content: [{ type: "text", text: (err as Error).message }] };
      }
    },
  );

  return mcpServer;
}
