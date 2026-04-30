import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AgentSession } from "../agent/index.js";
import type { EndpointRepository } from "../db/repositories/endpoint-repo.js";
import type { SshKeyRepository } from "../db/repositories/key-repo.js";
import { registerEndpointTools } from "./tools/endpoints.js";
import { registerKeyTools } from "./tools/keys.js";
import { registerSessionTools } from "./tools/sessions.js";

export async function createMcpServer(
  agentSession: AgentSession,
  endpointRepo: EndpointRepository,
  keyRepo: SshKeyRepository,
  accountId: string,
): Promise<McpServer> {
  const endpoints = await agentSession.listEndpoints();
  const endpointList = endpoints
    .map((s) => {
      const head = `- ${s.id}: ${s.label} (${s.username}@${s.host}:${s.port})`;
      return s.description ? `${head}\n  description: ${s.description}` : head;
    })
    .join("\n");

  const sudoSection = [
    "",
    "sudo:",
    "- Do NOT pass -n (non-interactive). The human operator can attach to your session and type the password directly, so a [sudo] password: prompt is not a failure mode.",
    "- If you see a [sudo] password: prompt, ask the operator (in your reply) to enter the password in the session, then continue once read_output shows the prompt has cleared.",
    "- Do NOT chain sudo commands with && or || (e.g., `sudo cmd1 && sudo cmd2`). When a prompt appears the operator can't tell which command it belongs to. Send each sudo command separately so every prompt is unambiguous.",
    "- Sudo auth may go through a PAM module the operator satisfies out-of-band (push notification, hardware token, etc.) and can take tens of seconds — possibly falling back to a password prompt if the out-of-band step is declined or times out. A stalled prompt is not failure: keep polling read_output until the prompt clears or you see an explicit denial.",
  ];

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
    ...sudoSection,
  ].join("\n");

  const mcpServer = new McpServer({ name: "shellwatch", version: "0.5.0" }, { instructions });

  // Capture the calling client's advertised clientInfo from the initialize
  // handshake so endpoint-auth sign requests can show "MCP Client" / version
  // in the self-reported approval UI box. The MCP SDK doesn't surface
  // clientInfo to per-tool handlers, so we cache it on the AgentSession.
  //
  // Per MCP spec the server rejects non-initialize requests until the
  // initialize handshake completes, so this fires before any tool call from
  // a spec-compliant client. A buggy client that skips initialize would
  // produce sign requests with no clientInfo (the UI hides those rows).
  // `oninitialized` is a single-slot field on the underlying Server — keep
  // this the only assignment.
  mcpServer.server.oninitialized = () => {
    const info = mcpServer.server.getClientVersion();
    if (info) agentSession.setMcpClientInfo(info);
  };

  registerSessionTools(mcpServer, agentSession);
  registerEndpointTools(mcpServer, endpointRepo, accountId);
  registerKeyTools(mcpServer, keyRepo);

  return mcpServer;
}
