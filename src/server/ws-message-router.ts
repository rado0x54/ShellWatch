import type { TerminalManager } from "../terminal/index.js";
import type { ClientMessage, ServerMessage, SessionMode } from "./ws-protocol.js";

export interface WsClientContext {
  attachedSessions: Set<string>;
  controlledSessions: Set<string>;
  send(msg: ServerMessage): void;
  sendError(message: string): void;
}

export interface WsRouterDeps {
  terminalManager: TerminalManager;
  uiCreatedSessions: Set<string>;
}

function getModeForSession(
  sessionId: string,
  terminalManager: TerminalManager,
  uiCreatedSessions: Set<string>,
): SessionMode {
  const session = terminalManager.getSession(sessionId);
  if (!session) return "observer";
  return uiCreatedSessions.has(sessionId) ? "control" : "observer";
}

export function buildSessionList(
  terminalManager: TerminalManager,
  controlledSessions: Set<string>,
  uiCreatedSessions: Set<string>,
): ServerMessage {
  return {
    type: "sessions:changed",
    sessions: terminalManager.listSessions().map((s) => ({
      sessionId: s.sessionId,
      endpointId: s.endpointId,
      status: s.status,
      createdAt: s.createdAt.toISOString(),
      source: s.source,
      mode: controlledSessions.has(s.sessionId)
        ? "control"
        : getModeForSession(s.sessionId, terminalManager, uiCreatedSessions),
    })),
  };
}

export function routeMessage(msg: ClientMessage, ctx: WsClientContext, deps: WsRouterDeps): void {
  const { terminalManager, uiCreatedSessions } = deps;
  const { attachedSessions, controlledSessions, send, sendError } = ctx;

  function hasControl(sessionId: string): boolean {
    return controlledSessions.has(sessionId) || uiCreatedSessions.has(sessionId);
  }

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

    case "terminal:detach": {
      attachedSessions.delete(msg.sessionId);
      controlledSessions.delete(msg.sessionId);
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
}
