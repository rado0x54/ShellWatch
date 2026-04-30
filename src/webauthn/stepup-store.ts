import { randomBytes } from "node:crypto";

/**
 * In-memory step-up token store. A step-up token is minted by a successful
 * WebAuthn assertion against an existing active credential on the caller's
 * account, and is then presented to a passkey-management endpoint to prove
 * fresh possession. Tokens are:
 *
 *   - Single-use (consumed on first read).
 *   - Action-bound (a token minted for "register" cannot be used for "revoke").
 *   - Account-bound (rejected if presented by a different session).
 *   - Short-lived (default 90 s).
 *
 * Tokens are NOT bound to a specific credential id — only to {account, action}.
 * Asserting with passkey Y is enough to revoke passkey X on the same account,
 * which is the explicit goal: revoking a *lost* authenticator means the user
 * has to assert with a different one. Same logic applies to `confirm_passkey`
 * (no "matching" credential exists yet for a brand-new pending row). The
 * trade-off is that any active credential authorises the action — if that's
 * ever too loose for a future flow, we'd need a `credentialId`-bound variant.
 *
 * Why in-memory: tokens live for ~90 s, so persistence has no recovery value.
 * Bound tightly to a single Node process — for multi-instance deployment this
 * needs to move into a shared cache (same caveat as challenge-store).
 */

const DEFAULT_TTL_MS = 90 * 1000;

export const STEPUP_ACTION = {
  registerPasskey: "register_passkey",
  revokePasskey: "revoke_passkey",
  confirmPasskey: "confirm_passkey",
} as const;

export type StepUpAction = (typeof STEPUP_ACTION)[keyof typeof STEPUP_ACTION];

export interface StepUpToken {
  token: string;
  accountId: string;
  action: StepUpAction;
  expiresAt: number;
}

export interface MintStepUpTokenParams {
  accountId: string;
  action: StepUpAction;
  /** Override TTL (used by tests). */
  ttlMs?: number;
}

const byToken = new Map<string, StepUpToken>();

function isExpired(token: StepUpToken, now: number): boolean {
  return token.expiresAt <= now;
}

function sweep(now: number): void {
  for (const [k, v] of byToken) {
    if (isExpired(v, now)) byToken.delete(k);
  }
}

/** Mint and store a fresh step-up token. */
export function mintStepUpToken(params: MintStepUpTokenParams): StepUpToken {
  const now = Date.now();
  sweep(now);
  const entry: StepUpToken = {
    token: randomBytes(32).toString("base64url"),
    accountId: params.accountId,
    action: params.action,
    expiresAt: now + (params.ttlMs ?? DEFAULT_TTL_MS),
  };
  byToken.set(entry.token, entry);
  return entry;
}

export type ConsumeFailureReason = "missing" | "expired" | "wrong_action" | "wrong_account";

export type ConsumeResult =
  | { ok: true; token: StepUpToken }
  | { ok: false; reason: ConsumeFailureReason };

export interface ConsumeStepUpTokenParams {
  token: string | undefined | null;
  accountId: string;
  action: StepUpAction;
}

/**
 * Consume a step-up token. The entry is removed from the store regardless of
 * whether the action/account match — a token is single-use, even if presented
 * to the wrong endpoint, so an attacker can't probe one token across actions.
 * Expired tokens are dropped silently and reported as `expired`.
 */
export function consumeStepUpToken(params: ConsumeStepUpTokenParams): ConsumeResult {
  const { token, accountId, action } = params;
  if (!token || typeof token !== "string") return { ok: false, reason: "missing" };

  const entry = byToken.get(token);
  if (!entry) return { ok: false, reason: "missing" };

  byToken.delete(entry.token);

  if (isExpired(entry, Date.now())) return { ok: false, reason: "expired" };
  if (entry.accountId !== accountId) return { ok: false, reason: "wrong_account" };
  if (entry.action !== action) return { ok: false, reason: "wrong_action" };

  return { ok: true, token: entry };
}

/** Test helper: drop all tokens. */
export function _resetStepUpStore(): void {
  byToken.clear();
}
