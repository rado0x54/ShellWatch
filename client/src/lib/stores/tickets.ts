// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * One-time access tickets (#306), owner side: mint, list and revoke. The
 * server pushes `tickets:changed` over /ws whenever a ticket or its guest
 * session changes state; the list is refetched then.
 */
import { writable } from "svelte/store";
import { apiFetch } from "../api.js";

export type TicketState = "minted" | "redeemed" | "pending" | "refused" | "open";

export interface TicketGuest {
  state: Exclude<TicketState, "minted">;
  channel: "web";
  confirmationCode: string;
  reason: string;
  sourceIp: string;
  userAgent: string;
  redeemedAt: string;
  admissionDeadline: string | null;
  lifetimeDeadline: string | null;
  sessionId: string | null;
  attempt: number;
  attached: boolean;
  connections: number;
}

export interface Ticket {
  id: string;
  endpointId: string;
  label: string;
  createdAt: string;
  expiresAt: string;
  redeemTtlSeconds: number;
  lifetimeSeconds: number;
  reasonRequired: boolean;
  agentForward: boolean;
  state: TicketState;
  guest: TicketGuest | null;
}

export interface MintOptions {
  label: string;
  redeemTtlSeconds: number;
  lifetimeSeconds: number;
  reasonRequired: boolean;
  agentForward: boolean;
}

/** The mint screen's defaults: the most restrictive value of each option. */
export const DEFAULT_MINT_OPTIONS: MintOptions = {
  label: "",
  redeemTtlSeconds: 300,
  lifetimeSeconds: 900,
  reasonRequired: true,
  agentForward: false,
};

/** Option bounds (seconds), mirrored from the server. */
export const REDEEM_TTL_BOUNDS = { min: 60, max: 86_400 } as const;
export const LIFETIME_BOUNDS = { min: 60, max: 28_800 } as const;

export const tickets = writable<Ticket[]>([]);

export async function fetchTickets(): Promise<void> {
  const res = await apiFetch("/api/tickets");
  if (!res.ok) return;
  const data = (await res.json()) as { tickets: Ticket[] };
  tickets.set(data.tickets);
}

async function errorFrom(res: Response, fallback: string): Promise<Error> {
  try {
    const body = (await res.json()) as { error?: string };
    return new Error(body.error || fallback);
  } catch {
    return new Error(fallback);
  }
}

/** Mint a ticket; returns it with its token (shown exactly once). */
export async function mintTicket(
  endpointId: string,
  opts: MintOptions,
): Promise<{ ticket: Ticket; token: string }> {
  const res = await apiFetch(`/api/endpoints/${encodeURIComponent(endpointId)}/tickets`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(opts),
  });
  if (res.status !== 201) throw await errorFrom(res, "Failed to create the access link");
  const out = (await res.json()) as { ticket: Ticket; token: string };
  await fetchTickets();
  return out;
}

/** Revoke a ticket in any state (ends its guest session). */
export async function revokeTicket(id: string): Promise<void> {
  const res = await apiFetch(`/api/tickets/${encodeURIComponent(id)}`, { method: "DELETE" });
  if (!res.ok && res.status !== 404) throw await errorFrom(res, "Failed to revoke the ticket");
  await fetchTickets();
}

/** The share link for a token: the token rides in the fragment, which never
 * reaches a server log or a Referer. */
export function shareLink(token: string, origin: string = window.location.origin): string {
  return `${origin}/t#${token}`;
}

/** Human labels for the owner's view of a ticket's state. */
export function ticketStateLabel(t: Ticket): string {
  switch (t.state) {
    case "minted":
      return "not used yet";
    case "redeemed":
      return "opened, connecting";
    case "pending":
      return "waiting for approval";
    case "refused":
      return "not admitted (guest may ask again)";
    case "open":
      return t.guest?.attached ? "guest connected" : "guest disconnected";
  }
}
