import { randomUUID } from "node:crypto";

// In-memory challenge store (keyed by challenge ID, expires after 5 minutes)
const pendingChallenges = new Map<string, { challenge: string; expires: number }>();

/** Store a challenge and return its ID */
export function storeChallenge(challenge: string): string {
  const challengeId = randomUUID();
  pendingChallenges.set(challengeId, {
    challenge,
    expires: Date.now() + 5 * 60 * 1000,
  });

  // Clean up expired challenges
  for (const [id, { expires }] of pendingChallenges) {
    if (expires < Date.now()) pendingChallenges.delete(id);
  }

  return challengeId;
}

/** Consume a pending challenge — returns the challenge string or null if expired/missing */
export function consumeChallenge(challengeId: string): string | null {
  const pending = pendingChallenges.get(challengeId);
  if (!pending || pending.expires < Date.now()) {
    pendingChallenges.delete(challengeId);
    return null;
  }
  pendingChallenges.delete(challengeId);
  return pending.challenge;
}
