import type { TerminalStatus } from "../terminal/index.js";

// Client -> Server messages
export type ClientMessage =
  | { type: "terminal:attach"; sessionId: string }
  | { type: "terminal:input"; sessionId: string; data: string }
  | { type: "terminal:resize"; sessionId: string; cols: number; rows: number }
  | { type: "terminal:close"; sessionId: string }
  | { type: "terminal:take-control"; sessionId: string };

export type SessionMode = "control" | "observer";

export interface SessionListEntry {
  sessionId: string;
  endpointId: string;
  status: TerminalStatus;
  createdAt: string;
  source: string;
  mode: SessionMode;
}

// Server -> Client messages
export type ServerMessage =
  | { type: "terminal:output"; sessionId: string; data: string }
  | { type: "terminal:status"; sessionId: string; status: TerminalStatus }
  | { type: "terminal:closed"; sessionId: string }
  | { type: "terminal:mode"; sessionId: string; mode: SessionMode }
  | { type: "sessions:changed"; sessions: SessionListEntry[] }
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
