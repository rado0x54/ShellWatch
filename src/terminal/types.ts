import { randomUUID } from "node:crypto";

export type TerminalStatus = "opening" | "open" | "closing" | "closed" | "error";
export type TerminalSource = "ui" | "mcp" | "ssh";

export interface TerminalSession {
  sessionId: string;
  endpointId: string;
  /** Owning account (copied from endpoint.accountId at create time; immutable for the session's lifetime). */
  accountId: string;
  status: TerminalStatus;
  createdAt: Date;
  lastActivityAt: Date;
  source: TerminalSource;
}

export interface OutputReadResult {
  data: string;
  offset: number;
  hasMore: boolean;
}

export type TerminalEventMap = {
  output: [{ sessionId: string; data: string; offset: number }];
  "status-change": [{ sessionId: string; status: TerminalStatus; previousStatus: TerminalStatus }];
  close: [{ sessionId: string }];
};

export function generateSessionId(): string {
  return `sess_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
}
