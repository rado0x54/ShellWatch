// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { randomUUID } from "node:crypto";

/**
 * Challenge purpose tags. The store is shared across all WebAuthn flows
 * (login, self-register, in-account register, invite register, step-up), and
 * the purpose tag binds each minted challenge to the flow it was minted for
 * so a captured assertion can't be replayed against a sibling endpoint.
 *
 * Step-up purposes embed the action so a `register_passkey` assertion can't
 * be re-targeted as a `revoke_passkey` token grant.
 */
export const CHALLENGE_PURPOSE = {
  login: "auth:login",
  selfRegister: "auth:register",
  registerInAccount: "register:in_account",
  registerInvite: "register:invite",
  stepupRegisterPasskey: "stepup:register_passkey",
  stepupRevokePasskey: "stepup:revoke_passkey",
  stepupConfirmPasskey: "stepup:confirm_passkey",
} as const;

export type ChallengePurpose = (typeof CHALLENGE_PURPOSE)[keyof typeof CHALLENGE_PURPOSE];

/**
 * In-memory challenge store (keyed by challenge ID, expires after 5 minutes).
 * For multi-instance deployment this needs to move into a shared cache.
 *
 * Each challenge is tagged with a `purpose` string at store time and the
 * consumer must present the same purpose. This binds the challenge to the
 * flow it was minted for and prevents cross-flow replay — e.g. a step-up
 * assertion captured by an XSS attacker can't be re-targeted from
 * `stepup:register_passkey` to `stepup:revoke_passkey`, because the consume
 * call from `/stepup/verify` checks the purpose of the stored challenge
 * against the action submitted in the request body.
 *
 * Different ceremony types (registration vs authentication) are already kept
 * apart by @simplewebauthn (clientDataJSON.type binding); the purpose check
 * adds same-type cross-flow defence on top of that.
 */
const pendingChallenges = new Map<
  string,
  { challenge: string; purpose: string; expires: number }
>();

/**
 * Store a challenge bound to a purpose and return its ID. The same purpose
 * string must be passed to `consumeChallenge` or the lookup fails.
 */
export function storeChallenge(challenge: string, purpose: ChallengePurpose): string {
  const challengeId = randomUUID();
  pendingChallenges.set(challengeId, {
    challenge,
    purpose,
    expires: Date.now() + 5 * 60 * 1000,
  });

  // Clean up expired challenges
  for (const [id, { expires }] of pendingChallenges) {
    if (expires < Date.now()) pendingChallenges.delete(id);
  }

  return challengeId;
}

/**
 * Consume a pending challenge — returns the challenge string or null if
 * expired, missing, or stored under a different purpose. The entry is
 * removed even on a purpose mismatch (single-use; an attacker can't probe
 * one challenge across purposes).
 */
export function consumeChallenge(
  challengeId: string,
  expectedPurpose: ChallengePurpose,
): string | null {
  const pending = pendingChallenges.get(challengeId);
  if (!pending) return null;
  pendingChallenges.delete(challengeId);
  if (pending.expires < Date.now()) return null;
  if (pending.purpose !== expectedPurpose) return null;
  return pending.challenge;
}
