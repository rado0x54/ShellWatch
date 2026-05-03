// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import type { WebSocket } from "ws";

/**
 * Extension point for the WebSocket handler.
 * Allows external modules to hook into WS lifecycle events
 * without the WS handler needing to know about them.
 */
export interface WsExtension {
  /**
   * Called when a new WebSocket client connects. The WS handler rejects
   * unauthenticated connections at the door, so accountId is always set.
   *
   * Extensions are responsible for their own account scoping when handling
   * messages — the router's session ownership check does not apply to
   * extension-handled messages.
   */
  onConnect(socket: WebSocket, accountId: string): void;
  /** Called when a WebSocket client disconnects. */
  onDisconnect(socket: WebSocket): void;
  /**
   * Called for each incoming message. Return true if handled,
   * false to let other extensions or the default handler process it.
   */
  onMessage(msg: Record<string, unknown>, socket: WebSocket): boolean;
}
