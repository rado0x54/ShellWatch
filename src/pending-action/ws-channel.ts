import type { WebSocket } from "ws";
import type { WsExtension } from "../server/ws-extension.js";
import type { NotificationChannel } from "./dispatcher.js";
import type { PendingAction } from "./types.js";

interface TrackedClient {
  socket: WebSocket;
  accountId: string;
}

/**
 * WebSocket notification channel for PendingAction sign requests.
 *
 * Also implements WsExtension to track account-scoped browser connections
 * and handle action resolution broadcasts.
 */
export class WebSocketChannel implements NotificationChannel, WsExtension {
  readonly name = "websocket";
  private clients: TrackedClient[] = [];

  // --- NotificationChannel ---

  async send(action: PendingAction, deepLink: string): Promise<void> {
    const msg = JSON.stringify({
      type: "sign:request",
      actionId: action.id,
      deepLink,
      source: action.context.source,
      passkeyLabel: action.passkeyLabel,
      credentialId: action.credentialId,
      challenge: action.challenge,
      rpId: action.rpId,
      ...("endpointLabel" in action.context && {
        endpointLabel: action.context.endpointLabel,
      }),
      ...("endpointAddress" in action.context && {
        endpointAddress: action.context.endpointAddress,
      }),
    });
    for (const client of this.getOpenClientsForAccount(action.accountId)) {
      client.socket.send(msg);
    }
  }

  /** Broadcast that an action has reached a terminal state (so toasts can be cleared). */
  broadcastResolved(actionId: string, accountId: string): void {
    const msg = JSON.stringify({ type: "sign:resolved", actionId });
    for (const client of this.getOpenClientsForAccount(accountId)) {
      client.socket.send(msg);
    }
  }

  // --- WsExtension ---

  onConnect(socket: WebSocket, accountId: string | undefined): void {
    if (!accountId) return;
    this.clients.push({ socket, accountId });
  }

  onDisconnect(socket: WebSocket): void {
    this.clients = this.clients.filter((c) => c.socket !== socket);
  }

  onMessage(_msg: Record<string, unknown>, _socket: WebSocket): boolean {
    // This channel does not handle incoming WS messages — resolution
    // goes through the REST API.
    return false;
  }

  /** Check if any browser clients are connected for the given account. */
  hasClientsForAccount(accountId: string): boolean {
    return this.getOpenClientsForAccount(accountId).length > 0;
  }

  private getOpenClientsForAccount(accountId: string): TrackedClient[] {
    return this.clients.filter(
      (c) => c.accountId === accountId && c.socket.readyState === c.socket.OPEN,
    );
  }
}
