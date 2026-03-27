import type { FastifyInstance } from "fastify";
import type { WebSocket } from "ws";
import type { TerminalManager } from "../terminal/index.js";
import { parseClientMessage, type ServerMessage } from "./ws-protocol.js";

export function registerWebSocket(app: FastifyInstance, terminalManager: TerminalManager) {
  const clients = new Set<WebSocket>();

  function broadcast(msg: ServerMessage) {
    const data = JSON.stringify(msg);
    for (const client of clients) {
      if (client.readyState === client.OPEN) {
        client.send(data);
      }
    }
  }

  function buildSessionList(): ServerMessage {
    return {
      type: "sessions:changed",
      sessions: terminalManager.listSessions().map((s) => ({
        sessionId: s.sessionId,
        endpointId: s.endpointId,
        status: s.status,
        createdAt: s.createdAt.toISOString(),
        source: s.source,
      })),
    };
  }

  // Broadcast session list changes to ALL connected clients
  terminalManager.on("status-change", () => {
    broadcast(buildSessionList());
  });

  app.get("/ws", { websocket: true }, (socket: WebSocket) => {
    clients.add(socket);
    const attachedSessions = new Set<string>();

    function send(msg: ServerMessage) {
      if (socket.readyState === socket.OPEN) {
        socket.send(JSON.stringify(msg));
      }
    }

    function sendError(message: string) {
      send({ type: "error", message });
    }

    // Send current session list on connect
    send(buildSessionList());

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

      try {
        switch (msg.type) {
          case "terminal:attach": {
            const session = terminalManager.getSession(msg.sessionId);
            if (!session) {
              sendError(`Session not found: ${msg.sessionId}`);
              return;
            }
            attachedSessions.add(msg.sessionId);
            send({ type: "terminal:status", sessionId: msg.sessionId, status: session.status });

            // Send any buffered output so the client catches up
            const buffered = terminalManager.readOutput(msg.sessionId);
            if (buffered.data.length > 0) {
              send({ type: "terminal:output", sessionId: msg.sessionId, data: buffered.data });
            }
            break;
          }

          case "terminal:input": {
            terminalManager.sendInput(msg.sessionId, msg.data);
            break;
          }

          case "terminal:resize": {
            terminalManager.resize(msg.sessionId, msg.cols, msg.rows);
            break;
          }

          case "terminal:close": {
            terminalManager.close(msg.sessionId);
            break;
          }
        }
      } catch (err) {
        sendError((err as Error).message);
      }
    });

    socket.on("close", () => {
      clients.delete(socket);
      terminalManager.off("output", onOutput);
      terminalManager.off("close", onClose);
      attachedSessions.clear();
    });
  });
}
