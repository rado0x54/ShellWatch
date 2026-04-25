import type { EndpointRepository } from "../db/index.js";
import type { TerminalManager, TerminalSession } from "../terminal/index.js";
import type { ClientMessage, ServerMessage, SessionMode } from "./ws-protocol.js";

export interface WsClientContext {
  attachedSessions: Set<string>;
  controlledSessions: Set<string>;
  accountId: string | undefined;
  send(msg: ServerMessage): void;
  sendError(message: string): void;
}

export interface WsRouterDeps {
  terminalManager: TerminalManager;
  uiCreatedSessions: Set<string>;
  endpointRepo: EndpointRepository;
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
  allowedEndpointIds: Set<string>,
): ServerMessage {
  return {
    type: "sessions:changed",
    sessions: terminalManager
      .listSessions()
      .filter((s) => allowedEndpointIds.has(s.endpointId))
      .map((s) => ({
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

export async function routeMessage(
  msg: ClientMessage,
  ctx: WsClientContext,
  deps: WsRouterDeps,
): Promise<void> {
  const { terminalManager, uiCreatedSessions, endpointRepo } = deps;
  const { attachedSessions, controlledSessions, accountId, send, sendError } = ctx;

  async function ownsSession(session: TerminalSession): Promise<boolean> {
    if (!accountId) return false;
    const endpoint = await endpointRepo.findByIdForAccount(session.endpointId, accountId);
    return endpoint !== null;
  }

  function hasControl(sessionId: string): boolean {
    return controlledSessions.has(sessionId) || uiCreatedSessions.has(sessionId);
  }

  switch (msg.type) {
    case "terminal:attach": {
      const session = terminalManager.getSession(msg.sessionId);
      if (!session || !(await ownsSession(session))) {
        // Don't disclose existence of sessions on other accounts' endpoints.
        sendError(`Session not found: ${msg.sessionId}`);
        return;
      }
      attachedSessions.add(msg.sessionId);
      const mode: SessionMode = hasControl(msg.sessionId) ? "control" : "observer";
      send({ type: "terminal:status", sessionId: msg.sessionId, status: session.status });
      send({ type: "terminal:mode", sessionId: msg.sessionId, mode });

      // Send buffered output so the client catches up. If `afterOffset` is
      // provided, only the delta; if the offset has been evicted from the
      // ring, send the full buffer with reset=true so xterm clears first.
      const buffered = terminalManager.readOutputFrom(msg.sessionId, msg.afterOffset);
      if (buffered.data.length > 0 || buffered.reset) {
        send({
          type: "terminal:output",
          sessionId: msg.sessionId,
          data: buffered.data,
          offset: buffered.offset,
          ...(buffered.reset ? { reset: true as const } : {}),
        });
      }
      break;
    }

    case "terminal:detach": {
      attachedSessions.delete(msg.sessionId);
      controlledSessions.delete(msg.sessionId);
      break;
    }

    case "terminal:input": {
      // Attach was gated by ownership; require it before accepting input so a
      // client cannot send input to a session it doesn't own by guessing the
      // sessionId (uiCreatedSessions is a global set and not account-scoped).
      if (!attachedSessions.has(msg.sessionId)) {
        sendError(`Session not attached: ${msg.sessionId}`);
        return;
      }
      if (!hasControl(msg.sessionId)) {
        sendError("Observer mode: take control first to send input");
        return;
      }
      terminalManager.sendInput(msg.sessionId, msg.data);
      break;
    }

    case "terminal:resize": {
      if (!attachedSessions.has(msg.sessionId)) return;
      if (!hasControl(msg.sessionId)) {
        return;
      }
      terminalManager.resize(msg.sessionId, msg.cols, msg.rows);
      break;
    }

    case "terminal:close": {
      const session = terminalManager.getSession(msg.sessionId);
      if (!session || !(await ownsSession(session))) {
        sendError(`Session not found: ${msg.sessionId}`);
        return;
      }
      terminalManager.close(msg.sessionId);
      uiCreatedSessions.delete(msg.sessionId);
      break;
    }

    case "terminal:take-control": {
      const session = terminalManager.getSession(msg.sessionId);
      if (!session || !(await ownsSession(session))) {
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
