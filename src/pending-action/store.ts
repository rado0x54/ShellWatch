// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import type { SignResponse } from "../webauthn/ssh-agent.js";
import type { CreateActionParams, PendingAction, PendingActionEventMap } from "./types.js";

const ACTION_TTL_MS = 60_000;
const SWEEP_INTERVAL_MS = 10_000;

/** Generate a short, URL-safe ID (16 bytes -> 22 chars base64url). */
function generateActionId(): string {
  return randomBytes(16).toString("base64url");
}

/**
 * In-memory store for pending sign/approval actions.
 *
 * Emits typed events so observers (e.g. the audit writer for #186) can record
 * each transition without the store needing to know about persistence:
 *
 *   "created"  — fired after a new action is added.
 *   "resolved" — fired on every terminal transition (approved | denied |
 *                expired | cancelled) with the outcome label and timestamp.
 *
 * The audit log uses richer outcome labels than the in-memory `status` field:
 * cancelForConnection sets `status: "denied"` but emits `outcome: "cancelled"`.
 */
export class PendingActionStore extends EventEmitter<PendingActionEventMap> {
  private actions = new Map<string, PendingAction>();
  private timer: ReturnType<typeof setInterval>;

  constructor() {
    super();
    this.timer = setInterval(() => this.sweep(), SWEEP_INTERVAL_MS);
  }

  create(params: CreateActionParams): PendingAction {
    const now = Date.now();
    // Cast is safe: CreateActionParams is a union of complete action shapes minus the
    // four fields we add here (id, status, createdAt, expiresAt). TypeScript can't
    // narrow a spread on a union type, but the result is always a valid PendingAction.
    const action = {
      ...params,
      id: generateActionId(),
      status: "pending" as const,
      createdAt: now,
      expiresAt: now + ACTION_TTL_MS,
    } as PendingAction;
    this.actions.set(action.id, action);
    this.emit("created", action);
    return action;
  }

  get(id: string): PendingAction | undefined {
    return this.actions.get(id);
  }

  findPendingForAccount(accountId: string): PendingAction[] {
    const result: PendingAction[] = [];
    for (const action of this.actions.values()) {
      if (action.accountId === accountId && action.status === "pending") {
        result.push(action);
      }
    }
    return result;
  }

  resolve(id: string, response?: SignResponse): boolean {
    const action = this.actions.get(id);
    if (!action || action.status !== "pending") return false;
    if (action.type === "webauthn-sign" && !response) return false;
    action.status = "completed";
    if (action.type === "webauthn-sign") {
      action.resolve(response!);
    } else {
      action.resolve();
    }
    this.emit("resolved", { action, outcome: "approved", resolvedAt: Date.now() });
    return true;
  }

  /**
   * Cancel every pending action tied to a given SSH connection. Used when the
   * owning ssh2 Client closes or errors out so sibling sign prompts don't sit
   * on-screen waiting to sign into a session that no longer exists. Returns the
   * affected actions (after mutation) so the caller can broadcast resolution.
   */
  cancelForConnection(connectionId: string, reason: string): PendingAction[] {
    const cancelled: PendingAction[] = [];
    const at = Date.now();
    for (const action of this.actions.values()) {
      if (action.status !== "pending") continue;
      if (action.connectionId !== connectionId) continue;
      // Intentionally don't call action.reject: every current action.reject
      // closure (see PendingActionBase.reject) ultimately feeds the ssh2 sign
      // callback on the client we're tearing down. Calling it would be a
      // gesture against a dead client. Marking denied + letting the caller
      // broadcast is enough to clear UI state.
      action.status = "denied";
      cancelled.push(action);
      this.emit("resolved", {
        action,
        outcome: "cancelled",
        resolvedAt: at,
        cancelReason: reason,
      });
    }
    return cancelled;
  }

  deny(id: string): boolean {
    const action = this.actions.get(id);
    if (!action || action.status !== "pending") return false;
    action.status = "denied";
    action.reject(new Error("User denied signing request"));
    this.emit("resolved", { action, outcome: "denied", resolvedAt: Date.now() });
    return true;
  }

  destroy(): void {
    clearInterval(this.timer);
    const at = Date.now();
    for (const action of this.actions.values()) {
      if (action.status === "pending") {
        action.status = "expired";
        action.reject(new Error("PendingActionStore destroyed"));
        this.emit("resolved", { action, outcome: "expired", resolvedAt: at });
      }
    }
    this.actions.clear();
    this.removeAllListeners();
  }

  private sweep(): void {
    const now = Date.now();
    for (const [id, action] of this.actions) {
      if (action.status === "pending" && now >= action.expiresAt) {
        action.status = "expired";
        action.reject(new Error("Signing request expired — no response within 60 seconds"));
        this.emit("resolved", { action, outcome: "expired", resolvedAt: now });
      }
      // Clean up terminal states older than 2 minutes (allows client to poll status)
      if (action.status !== "pending" && now - action.expiresAt > 120_000) {
        this.actions.delete(id);
      }
    }
  }
}
