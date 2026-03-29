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
      type: "fido:sign-request";
      requestId: string;
      credentialId: string;
      challenge: string;
      rpId: string;
    }
  | { type: "error"; message: string };

type MessageHandler = (msg: ServerMessage) => void;

export class WsClient {
  private ws: WebSocket | null = null;
  private handlers = new Set<MessageHandler>();
  private url: string;

  constructor() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    this.url = `${proto}//${location.host}/ws`;
  }

  connect(): void {
    this.ws = new WebSocket(this.url);

    this.ws.onopen = () => {};

    this.ws.onmessage = (event) => {
      try {
        const msg: ServerMessage = JSON.parse(event.data);
        for (const handler of this.handlers) {
          handler(msg);
        }
      } catch (err) {
        console.error(
          "[WsClient] Failed to parse message:",
          err,
          event.data?.toString().slice(0, 100),
        );
      }
    };

    this.ws.onclose = () => {
      setTimeout(() => this.connect(), 2000);
    };
  }

  onMessage(handler: MessageHandler): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  send(msg: Record<string, unknown>): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }

  attach(sessionId: string): void {
    this.send({ type: "terminal:attach", sessionId });
  }

  sendInput(sessionId: string, data: string): void {
    this.send({ type: "terminal:input", sessionId, data });
  }

  sendResize(sessionId: string, cols: number, rows: number): void {
    this.send({ type: "terminal:resize", sessionId, cols, rows });
  }

  closeSession(sessionId: string): void {
    this.send({ type: "terminal:close", sessionId });
  }

  takeControl(sessionId: string): void {
    this.send({ type: "terminal:take-control", sessionId });
  }
}
