// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * The guest page's one retry rule (#321). A reachable server answers every
 * `/ws/guest` handshake with a frame, and a closed frame ends the session.
 * So a failed handshake or a dropped socket only ever means "could not reach
 * the server": the page retries, first connect and later drop alike, and
 * gives up after the server's reconnect grace.
 */

/** The one ending text a guest sees, whatever the cause (the owner's audit
 * log has the real reason). */
export const ENDED = "The session has ended.";

/** Between two attempts. */
export const RECONNECT_DELAY_MS = 2000;

/** The server's reconnect grace (and longer than its attach window): past
 * it there is no session left to reach. */
export const RECONNECT_GIVE_UP_MS = 60_000;

/** How a guest session ends on the page: `invalid` shows "There is no active
 * guest session in this browser.", `ended` shows `message`. */
export type Ending = { phase: "invalid" } | { phase: "ended"; message: string };

/**
 * The ending for a closed frame (`message` from it) or a give-up (none).
 * Decided only by what this tab saw: a tab that never received a status had
 * no live session here (a reload after the session ended, or `/t` opened
 * without a link). A specific message (the window cap) is always shown: the
 * session itself goes on in the guest's other tabs.
 */
export function endingFor(sawStatus: boolean, message?: string): Ending {
  const text = message ?? ENDED;
  return !sawStatus && text === ENDED ? { phase: "invalid" } : { phase: "ended", message: text };
}

export type DropDecision = { retry: true; dropSince: number } | { retry: false; ending: Ending };

/** A handshake failed or the socket dropped at `now`; `dropSince` is when
 * the server was last lost without a status since (null: just now). */
export function onConnectionLost(
  dropSince: number | null,
  sawStatus: boolean,
  now: number,
): DropDecision {
  const since = dropSince ?? now;
  if (now - since > RECONNECT_GIVE_UP_MS) return { retry: false, ending: endingFor(sawStatus) };
  return { retry: true, dropSince: since };
}
