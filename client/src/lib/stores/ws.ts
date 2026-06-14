// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { writable } from "svelte/store";
import { beginLogin, getAccessToken, hasRefreshToken } from "../oauth.js";
import { addToast, clearAction, toastError, type SignRequestAction } from "./toasts.js";

/** Sentinel WS subprotocol carrying the bearer token; mirror of server bearer-gate.ts. */
const WS_BEARER_SUBPROTOCOL = "shellwatch.bearer";

/** Delay before a reconnect attempt after a drop. */
const RECONNECT_DELAY_MS = 2000;

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
  | { type: "terminal:output"; sessionId: string; data: string; offset: number; reset?: true }
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
const lastOffsetBySession = new Map<string, number>();

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

function scheduleReconnect(): void {
  // Reconnect with a FORCED refresh so a server-revoked (but client-cache-valid)
  // token is re-minted or fails fast — rather than looping with the same dead
  // token until it expires (#217). A live revoke-all therefore drops the socket
  // promptly: the forced refresh 4xx-clears the grant and we fall through to
  // login below.
  setTimeout(() => void connectWs({ force: true }), RECONNECT_DELAY_MS);
}

export async function connectWs(opts?: { force?: boolean }): Promise<void> {
  const token = await getAccessToken({ force: opts?.force });
  if (!token) {
    // No usable token. If we still hold a refresh token, this was a TRANSIENT
    // failure (Hydra 5xx / offline) — keep retrying rather than bouncing the
    // user out and losing terminal state. Only a truly-dead session (no refresh
    // token left — e.g. revoked) goes to sign-in.
    if (hasRefreshToken()) {
      scheduleReconnect();
      return;
    }
    await beginLogin(location.pathname + location.search);
    return;
  }

  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${proto}//${location.host}/ws`;
  // Browsers can't set an Authorization header on a WS handshake, so the token
  // rides in Sec-WebSocket-Protocol alongside the sentinel — keeps it out of
  // access logs (vs a query param). The bearer gate reads it from the header.
  ws = new WebSocket(url, [WS_BEARER_SUBPROTOCOL, token]);

  ws.onmessage = (event) => {
    try {
      const msg: ServerMessage = JSON.parse(event.data);

      if (msg.type === "sessions:changed") {
        sessions.set(msg.sessions);
      }

      if (msg.type === "terminal:output") {
        if (msg.reset) lastOffsetBySession.delete(msg.sessionId);
        lastOffsetBySession.set(msg.sessionId, msg.offset);
      }

      if (msg.type === "terminal:closed") {
        lastOffsetBySession.delete(msg.sessionId);
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

      if (msg.type === "error") {
        toastError(msg.message);
      }

      for (const handler of handlers) {
        handler(msg);
      }
    } catch (err) {
      console.error("[WsClient] Failed to parse message:", err);
    }
  };

  ws.onclose = () => {
    scheduleReconnect();
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

export function wsAttach(sessionId: string, options: { fresh?: boolean } = {}): void {
  if (options.fresh) lastOffsetBySession.delete(sessionId);
  const afterOffset = lastOffsetBySession.get(sessionId);
  wsSend({
    type: "terminal:attach",
    sessionId,
    ...(afterOffset !== undefined ? { afterOffset } : {}),
  });
}

export function wsDetach(sessionId: string): void {
  wsSend({ type: "terminal:detach", sessionId });
  lastOffsetBySession.delete(sessionId);
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
