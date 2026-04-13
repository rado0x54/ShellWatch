import { randomBytes } from "node:crypto";
import type { SignResponse } from "../webauthn/ssh-agent.js";
import type { CreateActionParams, PendingAction } from "./types.js";

const ACTION_TTL_MS = 60_000;
const SWEEP_INTERVAL_MS = 10_000;

/** Generate a short, URL-safe ID (16 bytes -> 22 chars base64url). */
function generateActionId(): string {
  return randomBytes(16).toString("base64url");
}

export class PendingActionStore {
  private actions = new Map<string, PendingAction>();
  private timer: ReturnType<typeof setInterval>;

  constructor() {
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
    return true;
  }

  /**
   * Cancel every pending action tied to a given SSH connection. Used when the
   * owning ssh2 Client closes or errors out so sibling sign prompts don't sit
   * on-screen waiting to sign into a session that no longer exists. Returns the
   * affected actions (after mutation) so the caller can broadcast resolution.
   */
  cancelForConnection(connectionId: string, _reason: string): PendingAction[] {
    const cancelled: PendingAction[] = [];
    for (const action of this.actions.values()) {
      if (action.status !== "pending") continue;
      if (action.connectionId !== connectionId) continue;
      // Intentionally don't call action.reject: the ssh2 client owning these
      // sign callbacks has already been torn down, so invoking its cb would
      // just be an empty gesture against a dead client. Marking the action
      // denied + broadcasting (caller's job) is enough to clear UI state.
      action.status = "denied";
      cancelled.push(action);
    }
    return cancelled;
  }

  deny(id: string): boolean {
    const action = this.actions.get(id);
    if (!action || action.status !== "pending") return false;
    action.status = "denied";
    action.reject(new Error("User denied signing request"));
    return true;
  }

  destroy(): void {
    clearInterval(this.timer);
    for (const action of this.actions.values()) {
      if (action.status === "pending") {
        action.status = "expired";
        action.reject(new Error("PendingActionStore destroyed"));
      }
    }
    this.actions.clear();
  }

  private sweep(): void {
    const now = Date.now();
    for (const [id, action] of this.actions) {
      if (action.status === "pending" && now >= action.expiresAt) {
        action.status = "expired";
        action.reject(new Error("Signing request expired — no response within 60 seconds"));
      }
      // Clean up terminal states older than 2 minutes (allows client to poll status)
      if (action.status !== "pending" && now - action.expiresAt > 120_000) {
        this.actions.delete(id);
      }
    }
  }
}
