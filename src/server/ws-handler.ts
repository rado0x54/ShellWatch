import type { FastifyInstance } from "fastify";
import type { WebSocket } from "ws";
import type { TerminalManager, TerminalStatus } from "../terminal/index.js";
import { parseClientMessage, type ServerMessage } from "./ws-protocol.js";

export function registerWebSocket(app: FastifyInstance, terminalManager: TerminalManager) {
  app.get("/ws", { websocket: true }, (socket: WebSocket) => {
    const attachedSessions = new Set<string>();

    function send(msg: ServerMessage) {
      if (socket.readyState === socket.OPEN) {
        socket.send(JSON.stringify(msg));
      }
    }

    function sendError(message: string) {
      send({ type: "error", message });
    }

    // Listeners for terminal events — scoped per attached session
    function onOutput({ sessionId, data }: { sessionId: string; data: string }) {
      if (attachedSessions.has(sessionId)) {
        send({ type: "terminal:output", sessionId, data });
      }
    }

    function onStatusChange({ sessionId, status }: { sessionId: string; status: TerminalStatus }) {
      if (attachedSessions.has(sessionId)) {
        send({ type: "terminal:status", sessionId, status });
      }
    }

    function onClose({ sessionId }: { sessionId: string }) {
      if (attachedSessions.has(sessionId)) {
        send({ type: "terminal:closed", sessionId });
        attachedSessions.delete(sessionId);
      }
    }

    terminalManager.on("output", onOutput);
    terminalManager.on("status-change", onStatusChange);
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
      // Clean up listeners — don't kill terminal sessions on WS disconnect
      terminalManager.off("output", onOutput);
      terminalManager.off("status-change", onStatusChange);
      terminalManager.off("close", onClose);
      attachedSessions.clear();
    });
  });
}
