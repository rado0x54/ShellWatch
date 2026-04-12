import type { SignResponse } from "../webauthn/ssh-agent.js";

// --- Source contexts (discriminated union) ---

export interface AgentProxyContext {
  source: "agent-proxy";
  sourceIp: string;
  apiKeyLabel: string;
  apiKeyPrefix: string;
  /** Client hostname advertised via X-ShellWatch-Hostname header on WS handshake. */
  clientHostname?: string;
  /** Client OS/arch (e.g. "darwin/arm64") advertised via X-ShellWatch-OS header. */
  clientOs?: string;
  /** Agent client version advertised via X-ShellWatch-Version header. */
  clientVersion?: string;
}

export type EndpointAuthTrigger =
  | { kind: "ui"; sourceIp?: string }
  | { kind: "mcp"; sourceIp?: string; mcpClientName?: string; mcpClientVersion?: string };

export interface EndpointAuthContext {
  source: "endpoint-auth";
  endpointLabel: string;
  endpointAddress: string;
  trigger: EndpointAuthTrigger;
}

export interface AgentForwardingContext {
  source: "agent-forwarding";
  endpointLabel: string;
  endpointAddress: string;
  sessionId: string;
}

export type SignRequestContext = AgentProxyContext | EndpointAuthContext | AgentForwardingContext;

// --- PendingAction (discriminated union on `type`) ---

export type PendingActionStatus = "pending" | "completed" | "expired" | "denied";

interface PendingActionBase {
  id: string;
  accountId: string;
  status: PendingActionStatus;
  createdAt: number;
  expiresAt: number;
  context: SignRequestContext;
  /** Optional path to navigate to after successful resolution (e.g. "/terminal/:id"). */
  redirectTo?: string;
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
