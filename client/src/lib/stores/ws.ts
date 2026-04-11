import { writable } from "svelte/store";
import { addToast, clearAction } from "./toasts.js";

export type SessionMode = "control" | "observer";

export interface SessionListEntry {
  sessionId: string;
  endpointId: string;
  status: string;
  createdAt: string;
  source: string;
  mode: SessionMode;
}

type ServerMessage =
  | { type: "terminal:output"; sessionId: string; data: string }
  | { type: "terminal:status"; sessionId: string; status: string }
  | { type: "terminal:closed"; sessionId: string }
  | { type: "terminal:mode"; sessionId: string; mode: SessionMode }
  | { type: "sessions:changed"; sessions: SessionListEntry[] }
  | {
      type: "sign:request";
      actionId: string;
      deepLink: string;
      source: string;
      passkeyLabel?: string;
      endpointLabel?: string;
      endpointAddress?: string;
      credentialId: string;
      challenge: string;
      rpId: string;
    }
  | { type: "sign:resolved"; actionId: string }
  | { type: "error"; message: string };

type MessageHandler = (msg: ServerMessage) => void;

export const sessions = writable<SessionListEntry[]>([]);

let ws: WebSocket | null = null;
const handlers = new Set<MessageHandler>();

export function connectWs(): void {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${proto}//${location.host}/ws`;

  ws = new WebSocket(url);

  ws.onmessage = (event) => {
    try {
      const msg: ServerMessage = JSON.parse(event.data);

      if (msg.type === "sessions:changed") {
        sessions.set(msg.sessions);
      }

      // Handle sign request → show toast
      if (msg.type === "sign:request") {
        addToast({
          variant: "sign-request",
          message: "Passkey signature requested",
          action: {
            actionId: msg.actionId,
            deepLink: msg.deepLink,
            source: msg.source,
            endpointLabel: msg.endpointLabel,
            endpointAddress: msg.endpointAddress,
            passkeyLabel: msg.passkeyLabel,
            credentialId: msg.credentialId,
            challenge: msg.challenge,
            rpId: msg.rpId,
          },
        });
      }

      // Handle sign resolved → clear toast
      if (msg.type === "sign:resolved") {
        clearAction(msg.actionId);
      }

      for (const handler of handlers) {
        handler(msg);
      }
    } catch (err) {
      console.error("[WsClient] Failed to parse message:", err);
    }
  };

  ws.onclose = () => {
    setTimeout(() => connectWs(), 2000);
  };
}

export function onWsMessage(handler: MessageHandler): () => void {
  handlers.add(handler);
  return () => handlers.delete(handler);
}

export function wsSend(msg: Record<string, unknown>): void {
  if (ws?.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(msg));
  }
}

export function wsAttach(sessionId: string): void {
  wsSend({ type: "terminal:attach", sessionId });
}

export function wsDetach(sessionId: string): void {
  wsSend({ type: "terminal:detach", sessionId });
}

export function wsSendInput(sessionId: string, data: string): void {
  wsSend({ type: "terminal:input", sessionId, data });
}

export function wsSendResize(sessionId: string, cols: number, rows: number): void {
  wsSend({ type: "terminal:resize", sessionId, cols, rows });
}

export function wsTakeControl(sessionId: string): void {
  wsSend({ type: "terminal:take-control", sessionId });
}

export function wsReleaseControl(sessionId: string): void {
  wsSend({ type: "terminal:release-control", sessionId });
}
