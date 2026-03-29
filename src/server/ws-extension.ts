import type { WebSocket } from "ws";

/**
 * Extension point for the WebSocket handler.
 * Allows external modules to hook into WS lifecycle events
 * without the WS handler needing to know about them.
 */
export interface WsExtension {
  /** Called when a new WebSocket client connects. */
  onConnect(socket: WebSocket): void;
  /** Called when a WebSocket client disconnects. */
  onDisconnect(socket: WebSocket): void;
  /**
   * Called for each incoming message. Return true if handled,
   * false to let other extensions or the default handler process it.
   */
  onMessage(msg: Record<string, unknown>, socket: WebSocket): boolean;
}
