import { randomUUID } from "node:crypto";

export type TerminalStatus = "opening" | "open" | "closing" | "closed" | "error";
export type TerminalSource = "ui" | "mcp" | "ssh";

/**
 * Why a session ended. Subset for #184 (audit log) — full plumbing with required
 * arg + exhaustive call-site coverage will land in #185.
 */
export type CloseReason =
  | "client.ui" // DELETE /api/sessions/:id
  | "client.mcp" // shellwatch_close_session tool
  | "client.ws" // WebSocket router close message
  | "agent-disconnect" // agent connection torn down with sessions still owned
  | "idle-timeout" // cleanupIdleTerminals
  | "account-deleted" // closeAllForAccount cascade
  | "server-hangup" // transport 'close' event
  | "transport-error" // transport 'error' event
  | "shutdown"; // TerminalManager.destroy

export interface TerminalSession {
  sessionId: string;
  endpointId: string;
  /** Owning account (copied from endpoint.accountId at create time; immutable for the session's lifetime). */
  accountId: string;
  status: TerminalStatus;
  createdAt: Date;
  lastActivityAt: Date;
  source: TerminalSource;
  /** Set when the session transitions to a terminal state (`closed` / `error`). */
  closeReason?: CloseReason;
  // --- Trigger metadata, captured at create time and used by the audit log (#184). ---
  /** Source IP of the caller that triggered session creation (may be unset for non-HTTP paths). */
  sourceIp?: string;
  /** Free-form intent string from MCP triggers (`shellwatch_create_session.reason`). */
  mcpReason?: string;
  /** MCP client name from the initialize handshake (sanitized). */
  mcpClientName?: string;
  /** MCP client version from the initialize handshake (sanitized). */
  mcpClientVersion?: string;
  /** Label of the API key used to authenticate the request that triggered creation. */
  apiKeyLabel?: string;
  /** Prefix (first ~8 chars) of the API key used. */
  apiKeyPrefix?: string;
}

export interface OutputReadResult {
  data: string;
  offset: number;
  hasMore: boolean;
}

export type TerminalEventMap = {
  output: [{ sessionId: string; data: string; offset: number }];
  "status-change": [
    {
      sessionId: string;
      status: TerminalStatus;
      previousStatus: TerminalStatus;
      reason?: CloseReason;
    },
  ];
  close: [{ sessionId: string; reason?: CloseReason }];
};

export function generateSessionId(): string {
  return `sess_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
}
