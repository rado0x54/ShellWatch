import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { TerminalManager } from "../terminal/index.js";
import type { McpSessionOwnership } from "./server.js";

export interface McpNotificationOptions {
  debounceMs: number;
}

/**
 * Attaches MCP notification dispatching for a specific MCP server session.
 * Only sends notifications for sessions owned by this MCP client.
 */
export function attachMcpNotifications(
  mcpServer: McpServer,
  terminalManager: TerminalManager,
  ownership: McpSessionOwnership,
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
    if (!ownership.ownedSessions.has(sessionId)) return;

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
          // Session may have been closed between debounce schedule and fire
        }
      }, options.debounceMs),
    );
  }

  function onStatusChange({ sessionId, status }: { sessionId: string; status: string }) {
    if (!ownership.ownedSessions.has(sessionId)) return;

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
