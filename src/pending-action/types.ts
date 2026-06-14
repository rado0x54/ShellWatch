// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import type { UserVerification } from "../db/repositories/endpoint-repo.js";
import type { SignResponse } from "../webauthn/ssh-agent.js";

// --- Source contexts (discriminated union) ---

export interface AgentProxyContext {
  source: "agent-proxy";
  sourceIp: string;
  /** Client hostname advertised via X-ShellWatch-Hostname header on WS handshake. */
  clientHostname?: string;
  /** Client OS/arch (e.g. "darwin/arm64") advertised via X-ShellWatch-OS header. */
  clientOs?: string;
  /** Agent client version advertised via X-ShellWatch-Version header. */
  clientVersion?: string;
}

/**
 * MCP triggers carry a `reason` string so the approval UI (and future audit
 * log, #16) can show the agent's stated intent — humans clicking through the
 * web UI already know what they meant, so the `ui` variant has no equivalent.
 * Used by the session-lifecycle audit log (#184).
 */
export type EndpointAuthTrigger =
  | { kind: "ui"; sourceIp?: string }
  | {
      kind: "mcp";
      reason: string;
      sourceIp?: string;
      mcpClientName?: string;
      mcpClientVersion?: string;
    };

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
  /**
   * Identifier for the SSH client connection that spawned this action. When set,
   * the store can cancel all actions for a connection when the client dies so
   * stranded sign prompts don't outlive the SSH session they were meant for.
   */
  connectionId?: string;
  /**
   * Reject the request. Every current producer (WebAuthnSshAgent,
   * CompositeSshAgent's file-key path, ForwardingAgent) ultimately feeds the
   * ssh2 sign callback on the owning SSH client — there are no other
   * awaiters. PendingActionStore.cancelForConnection relies on that invariant
   * to skip calling reject after the client has been torn down.
   */
  reject: (error: Error) => void;
}

export interface WebAuthnSignAction extends PendingActionBase {
  type: "webauthn-sign";
  credentialId: string;
  challenge: string;
  rpId: string;
  passkeyLabel?: string;
  /**
   * WebAuthn userVerification policy for the ceremony, typically taken from
   * the originating endpoint. Drives both the `credentials.get()` option on
   * the client and whether the server enforces UV on the resolve payload.
   */
  userVerification: UserVerification;
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

// --- Store events (audit-writer subscribes) ---

/**
 * Audit outcome for a signing request. Note this is a richer label than the
 * in-memory `PendingActionStatus`: the store collapses both deny and cancel
 * onto `status: "denied"`, while the audit log distinguishes them.
 */
export type SigningRequestOutcome = "approved" | "denied" | "expired" | "cancelled";

export interface PendingActionResolvedEvent {
  action: PendingAction;
  outcome: SigningRequestOutcome;
  /** Wall-clock ms when the terminal transition fired. */
  resolvedAt: number;
  /** Populated only when outcome === "cancelled" — propagated from cancelForConnection. */
  cancelReason?: string;
}

export type PendingActionEventMap = {
  created: [PendingAction];
  resolved: [PendingActionResolvedEvent];
};
