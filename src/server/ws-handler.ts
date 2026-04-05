import type { FastifyInstance } from "fastify";
import type { WebSocket } from "ws";
import type { TerminalManager } from "../terminal/index.js";
import { buildSessionList, routeMessage } from "./ws-message-router.js";
import type { WsExtension } from "./ws-extension.js";
import { parseClientMessage, type ServerMessage } from "./ws-protocol.js";

export interface WsHandler {
  /** Register an extension that hooks into WS lifecycle events. */
  addExtension(extension: WsExtension): void;
  /** Track sessions created via the UI (for control mode). */
  uiCreatedSessions: Set<string>;
}

export function registerWebSocket(
  app: FastifyInstance,
  terminalManager: TerminalManager,
  basePath = "",
): WsHandler {
  const clients = new Set<WebSocket>();
  const extensions: WsExtension[] = [];
  // Track which sessions were created via the UI (across all WS clients)
  const uiCreatedSessions = new Set<string>();

  // Per-client metadata
  const clientMeta = new Map<
    WebSocket,
    { attachedSessions: Set<string>; controlledSessions: Set<string> }
  >();

  // Broadcast session list changes to ALL connected clients
  terminalManager.on("status-change", () => {
    // Each client gets their own mode view — broadcast individually
    for (const client of clients) {
      if (client.readyState === client.OPEN) {
        const meta = clientMeta.get(client);
        if (meta) {
          client.send(
            JSON.stringify(
              buildSessionList(terminalManager, meta.controlledSessions, uiCreatedSessions),
            ),
          );
        }
      }
    }
  });

  app.get(`${basePath}/ws`, { websocket: true }, (socket: WebSocket) => {
    clients.add(socket);
    for (const ext of extensions) ext.onConnect(socket);
    const attachedSessions = new Set<string>();
    const controlledSessions = new Set<string>();
    clientMeta.set(socket, { attachedSessions, controlledSessions });

    function send(msg: ServerMessage) {
      if (socket.readyState === socket.OPEN) {
        socket.send(JSON.stringify(msg));
      }
    }

    function sendError(message: string) {
      send({ type: "error", message });
    }

    const ctx = { attachedSessions, controlledSessions, send, sendError };
    const deps = { terminalManager, uiCreatedSessions };

    // Send current session list on connect
    send(buildSessionList(terminalManager, controlledSessions, uiCreatedSessions));

    // Listeners for terminal events — scoped per attached session
    function onOutput({ sessionId, data }: { sessionId: string; data: string }) {
      if (attachedSessions.has(sessionId)) {
        send({ type: "terminal:output", sessionId, data });
      }
    }

    function onClose({ sessionId }: { sessionId: string }) {
      if (attachedSessions.has(sessionId)) {
        send({ type: "terminal:closed", sessionId });
        attachedSessions.delete(sessionId);
        controlledSessions.delete(sessionId);
      }
    }

    terminalManager.on("output", onOutput);
    terminalManager.on("close", onClose);

    socket.on("message", (raw: Buffer | string) => {
      const msg = parseClientMessage(typeof raw === "string" ? raw : raw.toString("utf-8"));
      if (!msg) {
        sendError("Invalid message format");
        return;
      }

      // Let extensions handle the message first
      const handled = extensions.some((ext) =>
        ext.onMessage(msg as Record<string, unknown>, socket),
      );
      if (handled) return;

      try {
        routeMessage(msg, ctx, deps);
      } catch (err) {
        sendError((err as Error).message);
      }
    });

    socket.on("close", () => {
      clients.delete(socket);
      for (const ext of extensions) ext.onDisconnect(socket);
      clientMeta.delete(socket);
      terminalManager.off("output", onOutput);
      terminalManager.off("close", onClose);
      attachedSessions.clear();
      controlledSessions.clear();
    });
  });

  return {
    addExtension(extension: WsExtension) {
      extensions.push(extension);
    },
    uiCreatedSessions,
  };
}
