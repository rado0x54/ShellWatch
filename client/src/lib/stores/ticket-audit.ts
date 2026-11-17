// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Ticket event log (#306): every event of the account's one-time access
 * tickets and guest sessions, keyset-paginated, newest first.
 */
import { apiFetch } from "../api.js";

export interface TicketEventRow {
  id: string;
  accountId: string;
  ticketId: string;
  /** minted | redeemed | attached | attempt-failed | admitted | detached |
   * reattached | ended | revoked | expired | invalidated — an open string, not
   * a union (rows from before #327 may read `retried`). */
  event: string;
  createdAt: string;
  endpointId: string;
  ticketLabel: string | null;
  channel: string | null;
  redeemTtlSeconds: number;
  lifetimeSeconds: number;
  reasonRequired: boolean;
  agentForward: boolean;
  /** Self-reported by the guest. */
  reason: string | null;
  sourceIp: string | null;
  /** Self-reported by the guest browser. */
  userAgent: string | null;
  confirmationCode: string | null;
  sessionId: string | null;
  /** Null since #327 (one connect per guest session). */
  attempt: number | null;
  endReason: string | null;
  durationMs: number | null;
}

export interface TicketEventPage {
  rows: TicketEventRow[];
  nextCursor: string | null;
}

export const TICKET_EVENTS = [
  "minted",
  "redeemed",
  "attached",
  "attempt-failed",
  "admitted",
  "detached",
  "reattached",
  "ended",
  "revoked",
  "expired",
  "invalidated",
] as const;

export async function fetchTicketEvents(
  filters: { ticketId?: string; event?: string } = {},
  cursor?: string,
  limit = 50,
): Promise<TicketEventPage> {
  const params = new URLSearchParams();
  if (filters.ticketId) params.set("ticketId", filters.ticketId);
  if (filters.event) params.set("event", filters.event);
  if (cursor) params.set("cursor", cursor);
  params.set("limit", String(limit));
  const res = await apiFetch(`/api/audit/tickets?${params}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || "Failed to fetch the ticket log");
  }
  return res.json();
}
