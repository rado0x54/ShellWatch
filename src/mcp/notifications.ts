import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { TerminalManager } from "../terminal/index.js";

export interface McpNotificationOptions {
  debounceMs: number;
}

/**
 * Attaches MCP notification dispatching to a TerminalManager for a specific MCP server session.
 * Sends debounced output_available and immediate session_status notifications.
 */
export function attachMcpNotifications(
  mcpServer: McpServer,
  terminalManager: TerminalManager,
  options: McpNotificationOptions,
) {
  const ownedSessions = new Set<string>();
  const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();

  function sendNotification(method: string, params: Record<string, unknown>) {
    try {
      mcpServer.server.notification({ method, params });
    } catch {
      // Server may be disconnected — ignore
    }
  }

  function onOutput({ sessionId }: { sessionId: string }) {
    if (!ownedSessions.has(sessionId)) return;

    // Debounce: reset timer on each chunk, fire after quiet period
    const existing = debounceTimers.get(sessionId);
    if (existing) clearTimeout(existing);

    debounceTimers.set(
      sessionId,
      setTimeout(() => {
        debounceTimers.delete(sessionId);
        const { offset } = terminalManager.readOutput(sessionId);
        sendNotification("notifications/shellwatch/output_available", {
          sessionId,
          offset,
        });
      }, options.debounceMs),
    );
  }

  function onStatusChange({ sessionId, status }: { sessionId: string; status: string }) {
    const session = terminalManager.getSession(sessionId);
    sendNotification("notifications/shellwatch/session_status", {
      sessionId,
      status,
      endpointId: session?.endpointId,
      source: session?.source,
    });

    // Clean up if session closed
    if (status === "closed" || status === "error") {
      ownedSessions.delete(sessionId);
      const timer = debounceTimers.get(sessionId);
      if (timer) {
        clearTimeout(timer);
        debounceTimers.delete(sessionId);
      }
    }
  }

  terminalManager.on("output", onOutput);
  terminalManager.on("status-change", onStatusChange);

  return {
    /** Register a session as owned by this MCP client */
    trackSession(sessionId: string) {
      ownedSessions.add(sessionId);
    },
    /** Clean up listeners and timers */
    destroy() {
      terminalManager.off("output", onOutput);
      terminalManager.off("status-change", onStatusChange);
      for (const timer of debounceTimers.values()) {
        clearTimeout(timer);
      }
      debounceTimers.clear();
      ownedSessions.clear();
    },
  };
}
