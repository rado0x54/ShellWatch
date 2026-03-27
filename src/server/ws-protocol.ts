import type { TerminalStatus } from "../terminal/index.js";

// Client -> Server messages
export type ClientMessage =
  | { type: "terminal:attach"; sessionId: string }
  | { type: "terminal:input"; sessionId: string; data: string }
  | { type: "terminal:resize"; sessionId: string; cols: number; rows: number }
  | { type: "terminal:close"; sessionId: string };

// Server -> Client messages
export type ServerMessage =
  | { type: "terminal:output"; sessionId: string; data: string }
  | { type: "terminal:status"; sessionId: string; status: TerminalStatus }
  | { type: "terminal:closed"; sessionId: string }
  | { type: "error"; message: string };

export function parseClientMessage(raw: string): ClientMessage | null {
  try {
    const msg = JSON.parse(raw);
    if (!msg || typeof msg.type !== "string") return null;
    return msg as ClientMessage;
  } catch {
    return null;
  }
}
