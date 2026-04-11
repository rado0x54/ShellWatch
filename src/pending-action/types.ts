import type { SignResponse } from "../webauthn/ssh-agent.js";

// --- Source contexts (discriminated union) ---

export interface AgentProxyContext {
  source: "agent-proxy";
  sourceIp: string;
  apiKeyPrefix: string;
}

export interface UiContext {
  source: "ui";
  sourceIp: string;
  endpointLabel: string;
  endpointAddress: string;
  sessionId: string;
}

export interface McpContext {
  source: "mcp";
  sourceIp: string;
  endpointLabel: string;
  endpointAddress: string;
  mcpClientName?: string;
  mcpClientVersion?: string;
  sessionId?: string;
}

export interface ForwardingAgentContext {
  source: "forwarding-agent";
  endpointLabel: string;
  endpointAddress: string;
  sessionId: string;
}

export type SignRequestContext =
  | AgentProxyContext
  | UiContext
  | McpContext
  | ForwardingAgentContext;

// --- PendingAction ---

export type PendingActionStatus = "pending" | "completed" | "expired" | "denied";

export interface PendingAction {
  id: string;
  type: "webauthn-sign";
  accountId: string;
  status: PendingActionStatus;
  createdAt: number;
  expiresAt: number;

  context: SignRequestContext;

  // WebAuthn payload
  credentialId: string;
  challenge: string;
  rpId: string;
  passkeyLabel?: string;

  // Server-only — close over the ssh2 callback
  resolve: (result: SignResponse) => void;
  reject: (error: Error) => void;
}

/** Fields required to create a PendingAction (store generates id, status, timestamps). */
export type CreateActionParams = Omit<PendingAction, "id" | "status" | "createdAt" | "expiresAt">;

/** Client-safe projection (excludes resolve/reject). */
export type PendingActionView = Omit<PendingAction, "resolve" | "reject">;

export function toActionView(action: PendingAction): PendingActionView {
  const { resolve: _r, reject: _rj, ...view } = action;
  return view;
}
