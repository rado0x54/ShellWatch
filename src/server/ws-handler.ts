import type { FastifyInstance } from "fastify";
import type { WebSocket } from "ws";
import type { TerminalManager } from "../terminal/index.js";
import type { WsExtension } from "./ws-extension.js";
import { parseClientMessage, type ServerMessage, type SessionMode } from "./ws-protocol.js";

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

  function getModeForSession(sessionId: string): SessionMode {
    const session = terminalManager.getSession(sessionId);
    if (!session) return "observer";
    // UI-created sessions get control, everything else starts as observer
    return uiCreatedSessions.has(sessionId) ? "control" : "observer";
  }

  function buildSessionList(controlledSessions: Set<string>): ServerMessage {
    return {
      type: "sessions:changed",
      sessions: terminalManager.listSessions().map((s) => ({
        sessionId: s.sessionId,
        endpointId: s.endpointId,
        status: s.status,
        createdAt: s.createdAt.toISOString(),
        source: s.source,
        mode: controlledSessions.has(s.sessionId) ? "control" : getModeForSession(s.sessionId),
      })),
    };
  }

  // Broadcast session list changes to ALL connected clients
  terminalManager.on("status-change", () => {
    // Each client gets their own mode view — broadcast individually
    for (const client of clients) {
      if (client.readyState === client.OPEN) {
        const meta = clientMeta.get(client);
        if (meta) {
          client.send(JSON.stringify(buildSessionList(meta.controlledSessions)));
        }
      }
    }
  });

  // Per-client metadata
  const clientMeta = new Map<
    WebSocket,
    { attachedSessions: Set<string>; controlledSessions: Set<string> }
  >();

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

    function hasControl(sessionId: string): boolean {
      return controlledSessions.has(sessionId) || uiCreatedSessions.has(sessionId);
    }

    // Send current session list on connect
    send(buildSessionList(controlledSessions));

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
        switch (msg.type) {
          case "terminal:attach": {
            const session = terminalManager.getSession(msg.sessionId);
            if (!session) {
              sendError(`Session not found: ${msg.sessionId}`);
              return;
            }
            attachedSessions.add(msg.sessionId);
            const mode: SessionMode = hasControl(msg.sessionId) ? "control" : "observer";
            send({ type: "terminal:status", sessionId: msg.sessionId, status: session.status });
            send({ type: "terminal:mode", sessionId: msg.sessionId, mode });

            // Send any buffered output so the client catches up
            const buffered = terminalManager.readOutput(msg.sessionId);
            if (buffered.data.length > 0) {
              send({ type: "terminal:output", sessionId: msg.sessionId, data: buffered.data });
            }
            break;
          }

          case "terminal:input": {
            if (!hasControl(msg.sessionId)) {
              sendError("Observer mode: take control first to send input");
              return;
            }
            terminalManager.sendInput(msg.sessionId, msg.data);
            break;
          }

          case "terminal:resize": {
            if (!hasControl(msg.sessionId)) {
              return; // Silently ignore resize in observer mode
            }
            terminalManager.resize(msg.sessionId, msg.cols, msg.rows);
            break;
          }

          case "terminal:close": {
            terminalManager.close(msg.sessionId);
            uiCreatedSessions.delete(msg.sessionId);
            break;
          }

          case "terminal:take-control": {
            const session = terminalManager.getSession(msg.sessionId);
            if (!session) {
              sendError(`Session not found: ${msg.sessionId}`);
              return;
            }
            controlledSessions.add(msg.sessionId);
            send({ type: "terminal:mode", sessionId: msg.sessionId, mode: "control" });
            break;
          }

          case "terminal:release-control": {
            controlledSessions.delete(msg.sessionId);
            send({ type: "terminal:mode", sessionId: msg.sessionId, mode: "observer" });
            break;
          }
        }
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
