import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AgentSession } from "../agent/index.js";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { EndpointRepository } from "../db/repositories/endpoint-repo.js";
import type { SshKeyRepository } from "../db/repositories/key-repo.js";
import { registerEndpointTools } from "./tools/endpoints.js";
import { registerKeyTools } from "./tools/keys.js";
import { registerSessionTools } from "./tools/sessions.js";

export async function createMcpServer(
  agentSession: AgentSession,
  endpointRepo: EndpointRepository,
  keyRepo: SshKeyRepository,
  accountId?: string | null,
  accountRepo?: AccountRepository | null,
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

  registerSessionTools(mcpServer, agentSession);
  registerEndpointTools(mcpServer, endpointRepo, accountId, accountRepo);
  registerKeyTools(mcpServer, keyRepo);

  return mcpServer;
}
