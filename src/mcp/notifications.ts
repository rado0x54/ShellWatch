// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AgentSession } from "../agent/index.js";
import type { TerminalManager } from "../terminal/index.js";

export interface McpNotificationOptions {
  debounceMs: number;
}

/**
 * Attaches MCP notification dispatching for an agent session.
 * Only sends notifications for sessions owned by the agent.
 */
export function attachMcpNotifications(
  mcpServer: McpServer,
  terminalManager: TerminalManager,
  agentSession: AgentSession,
  options: McpNotificationOptions,
) {
  const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();

  function sendNotification(method: string, params: Record<string, unknown>) {
    try {
      mcpServer.server.notification({ method, params });
    } catch {
      // Server may be disconnected
    }
  }

  function onOutput({ sessionId }: { sessionId: string }) {
    if (!agentSession.sessions.has(sessionId)) return;

    const existing = debounceTimers.get(sessionId);
    if (existing) clearTimeout(existing);

    debounceTimers.set(
      sessionId,
      setTimeout(() => {
        debounceTimers.delete(sessionId);
        try {
          const { offset } = terminalManager.readOutput(sessionId);
          sendNotification("notifications/shellwatch/output_available", {
            sessionId,
            offset,
          });
        } catch {
          // Session may have been closed
        }
      }, options.debounceMs),
    );
  }

  function onStatusChange({ sessionId, status }: { sessionId: string; status: string }) {
    if (!agentSession.sessions.has(sessionId)) return;

    const session = terminalManager.getSession(sessionId);
    sendNotification("notifications/shellwatch/session_status", {
      sessionId,
      status,
      endpointId: session?.endpointId,
    });
  }

  terminalManager.on("output", onOutput);
  terminalManager.on("status-change", onStatusChange);

  return {
    destroy() {
      terminalManager.off("output", onOutput);
      terminalManager.off("status-change", onStatusChange);
      for (const timer of debounceTimers.values()) {
        clearTimeout(timer);
      }
      debounceTimers.clear();
    },
  };
}
