import { writable } from "svelte/store";
import { addToast, clearAction, type SignRequestAction } from "./toasts.js";

export type SessionMode = "control" | "observer";

export interface SessionListEntry {
  sessionId: string;
  endpointId: string;
  status: string;
  createdAt: string;
  source: string;
  mode: SessionMode;
}

type SignRequestMessage = {
  type: "sign:request";
  actionId: string;
  actionType: "webauthn-sign" | "key-approve";
  deepLink: string;
  source: string;
  endpointLabel?: string;
  endpointAddress?: string;
  // webauthn-sign fields
  passkeyLabel?: string;
  credentialId?: string;
  challenge?: string;
  rpId?: string;
  // key-approve fields
  keyLabel?: string;
  keyFingerprint?: string;
};

type ServerMessage =
  | { type: "terminal:output"; sessionId: string; data: string }
  | { type: "terminal:status"; sessionId: string; status: string }
  | { type: "terminal:closed"; sessionId: string }
  | { type: "terminal:mode"; sessionId: string; mode: SessionMode }
  | { type: "sessions:changed"; sessions: SessionListEntry[] }
  | SignRequestMessage
  | { type: "sign:resolved"; actionId: string }
  | { type: "error"; message: string };

type MessageHandler = (msg: ServerMessage) => void;

export const sessions = writable<SessionListEntry[]>([]);

let ws: WebSocket | null = null;
const handlers = new Set<MessageHandler>();

function buildActionFromMessage(msg: SignRequestMessage): SignRequestAction {
  const base = {
    actionId: msg.actionId,
    deepLink: msg.deepLink,
    source: msg.source,
    endpointLabel: msg.endpointLabel,
    endpointAddress: msg.endpointAddress,
  };

  if (msg.actionType === "key-approve") {
    return {
      ...base,
      actionType: "key-approve",
      keyLabel: msg.keyLabel!,
      keyFingerprint: msg.keyFingerprint!,
    };
  }

  return {
    ...base,
    actionType: "webauthn-sign",
    credentialId: msg.credentialId!,
    challenge: msg.challenge!,
    rpId: msg.rpId!,
    passkeyLabel: msg.passkeyLabel,
  };
}

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

      if (msg.type === "sign:request") {
        const message =
          msg.actionType === "key-approve"
            ? "SSH key approval requested"
            : "Passkey signature requested";
        addToast({
          variant: "sign-request",
          message,
          action: buildActionFromMessage(msg),
        });
      }

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
