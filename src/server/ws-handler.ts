import type { FastifyInstance } from "fastify";
import type { WebSocket } from "ws";
import type { EndpointRepository } from "../db/index.js";
import type { TerminalManager } from "../terminal/index.js";
import { buildSessionList, routeMessage } from "./ws-message-router.js";
import type { WsExtension } from "./ws-extension.js";
import { parseClientMessage, type ServerMessage } from "./ws-protocol.js";

export interface WsHandler {
  /** Register an extension that hooks into WS lifecycle events. */
  addExtension(extension: WsExtension): void;
}

export interface RegisterWebSocketParams {
  app: FastifyInstance;
  terminalManager: TerminalManager;
  uiCreatedSessions: Set<string>;
  endpointRepo: EndpointRepository;
}

export function registerWebSocket(params: RegisterWebSocketParams): WsHandler {
  const { app, terminalManager, uiCreatedSessions, endpointRepo } = params;
  const clients = new Set<WebSocket>();
  const extensions: WsExtension[] = [];

  // Per-client metadata
  const clientMeta = new Map<
    WebSocket,
    {
      attachedSessions: Set<string>;
      controlledSessions: Set<string>;
      accountId: string | undefined;
    }
  >();

  async function getAllowedEndpointIds(accountId: string | undefined): Promise<Set<string>> {
    if (!accountId) return new Set();
    const endpoints = await endpointRepo.findAllForAccount(accountId);
    return new Set(endpoints.map((e) => e.id));
  }

  // Broadcast session list changes to each client, scoped to their account
  terminalManager.on("status-change", () => {
    for (const client of clients) {
      if (client.readyState !== client.OPEN) continue;
      const meta = clientMeta.get(client);
      if (!meta) continue;
      void (async () => {
        try {
          const allowed = await getAllowedEndpointIds(meta.accountId);
          if (client.readyState !== client.OPEN) return;
          client.send(
            JSON.stringify(
              buildSessionList(
                terminalManager,
                meta.controlledSessions,
                uiCreatedSessions,
                allowed,
              ),
            ),
          );
        } catch (err) {
          app.log.error(err, "ws status-change broadcast failed");
        }
      })();
    }
  });

  app.get("/ws", { websocket: true }, (socket: WebSocket, request) => {
    const accountId = request.accountId ?? undefined;
    clients.add(socket);
    for (const ext of extensions) ext.onConnect(socket, accountId);
    const attachedSessions = new Set<string>();
    const controlledSessions = new Set<string>();
    clientMeta.set(socket, { attachedSessions, controlledSessions, accountId });

    function send(msg: ServerMessage) {
      if (socket.readyState === socket.OPEN) {
        socket.send(JSON.stringify(msg));
      }
    }

    function sendError(message: string) {
      send({ type: "error", message });
    }

    const ctx = { attachedSessions, controlledSessions, accountId, send, sendError };
    const deps = { terminalManager, uiCreatedSessions, endpointRepo };

    // Send current session list on connect (scoped to this account)
    void (async () => {
      try {
        const allowed = await getAllowedEndpointIds(accountId);
        send(buildSessionList(terminalManager, controlledSessions, uiCreatedSessions, allowed));
      } catch (err) {
        app.log.error(err, "ws initial session list failed");
      }
    })();

    // Listeners for terminal events — scoped per attached session
    function onOutput({
      sessionId,
      data,
      offset,
    }: {
      sessionId: string;
      data: string;
      offset: number;
    }) {
      if (attachedSessions.has(sessionId)) {
        send({ type: "terminal:output", sessionId, data, offset });
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

      void routeMessage(msg, ctx, deps).catch((err) => {
        sendError((err as Error).message);
      });
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
  };
}
