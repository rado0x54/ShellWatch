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
  sessionId?: string;
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
  sessionId?: string;
}

export type SignRequestContext =
  | AgentProxyContext
  | UiContext
  | McpContext
  | ForwardingAgentContext;

// --- PendingAction (discriminated union on `type`) ---

export type PendingActionStatus = "pending" | "completed" | "expired" | "denied";

interface PendingActionBase {
  id: string;
  accountId: string;
  status: PendingActionStatus;
  createdAt: number;
  expiresAt: number;
  context: SignRequestContext;
  reject: (error: Error) => void;
}

export interface WebAuthnSignAction extends PendingActionBase {
  type: "webauthn-sign";
  credentialId: string;
  challenge: string;
  rpId: string;
  passkeyLabel?: string;
  resolve: (result: SignResponse) => void;
}

export interface KeyApproveAction extends PendingActionBase {
  type: "key-approve";
  keyLabel: string;
  keyFingerprint: string;
  resolve: () => void;
}

export type PendingAction = WebAuthnSignAction | KeyApproveAction;

export type PendingActionType = PendingAction["type"];

/** Fields required to create a PendingAction (store generates id, status, timestamps). */
export type CreateActionParams =
  | Omit<WebAuthnSignAction, "id" | "status" | "createdAt" | "expiresAt">
  | Omit<KeyApproveAction, "id" | "status" | "createdAt" | "expiresAt">;

/** Client-safe projection (excludes resolve/reject). */
export type PendingActionView = Omit<PendingAction, "resolve" | "reject">;

export function toActionView(action: PendingAction): PendingActionView {
  const { resolve: _, reject: _r, ...view } = action;
  return view;
}
