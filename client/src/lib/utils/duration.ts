// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * A ticket's whole-minute duration for people: "15 min", "1 h", "8 h". Used
 * wherever a ticket's lifetime or link validity is shown (the approval page,
 * Guest access), so the two never read differently.
 */
export function formatTicketDuration(seconds: number): string {
  if (seconds > 0 && seconds % 3600 === 0) return `${seconds / 3600} h`;
  return `${Math.round(seconds / 60)} min`;
}
