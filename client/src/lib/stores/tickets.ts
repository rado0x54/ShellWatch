// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * One-time access tickets (#306), owner side: mint, list and revoke. The
 * server pushes `tickets:changed` over /ws whenever a ticket or its guest
 * session changes state; the list is refetched then.
 */
import { writable } from "svelte/store";
import { apiFetch } from "../api.js";

export type TicketState = "minted" | "redeemed" | "pending" | "refused" | "open" | "closed";

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
  /** Set once the guest session closed (state "closed"); the ticket stays
   * listed for 5 minutes. */
  endedAt: string | null;
  endReason: string | null;
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

/**
 * Server clock minus this device's clock (ms), from the list response's
 * `Date` header: the ticket deadlines are server times, so countdowns use
 * `Date.now() + offset`. 0 until known.
 */
export const ticketsClockOffset = writable(0);

export async function fetchTickets(): Promise<void> {
  const res = await apiFetch("/api/tickets");
  if (!res.ok) return;
  const date = Date.parse(res.headers.get("Date") ?? "");
  if (!Number.isNaN(date)) ticketsClockOffset.set(date - Date.now());
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
  // The token is shown exactly once: a failed list refresh must not turn a
  // successful mint into an error (the ticket exists either way).
  void fetchTickets().catch(() => {});
  return out;
}

/**
 * Revoke a live ticket (ends its guest session). "ended" when the guest
 * session had already ended or the ticket is gone: nothing changed, and an
 * ended ticket leaves the list on its own after 5 minutes.
 */
export async function revokeTicket(id: string): Promise<"revoked" | "ended"> {
  const res = await apiFetch(`/api/tickets/${encodeURIComponent(id)}`, { method: "DELETE" });
  if (!res.ok && res.status !== 404 && res.status !== 409) {
    throw await errorFrom(res, "Failed to revoke the ticket");
  }
  void fetchTickets().catch(() => {});
  return res.ok ? "revoked" : "ended";
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
    case "closed":
      return `ended: ${endReasonLabel(t.endReason)}`;
  }
}

/** Why a guest session ended, for people (the raw reason is the fallback). */
export function endReasonLabel(reason: string | null): string {
  switch (reason) {
    case "client.guest":
      return "ended by the guest";
    case "ticket-revoked":
      return "revoked";
    case "ticket-lifetime":
      return "time limit reached";
    case "ticket-not-admitted":
      return "not admitted";
    case "ticket-unattached":
      return "guest never connected";
    case "guest-disconnected":
      return "guest disconnected";
    case "endpoint-removed":
      return "endpoint deleted";
    case "idle-timeout":
      return "idle timeout";
    case "server-hangup":
      return "the remote host ended it";
    case "client.ui":
    case "client.ws":
      return "closed by you";
    case "shutdown":
      return "server shut down";
    case null:
      return "unknown";
    default:
      return reason;
  }
}

/** The guest-access page's three groups, newest first within each. */
export function groupTickets(list: Ticket[]): {
  active: Ticket[];
  invites: Ticket[];
  ended: Ticket[];
} {
  const newest = (a: Ticket, b: Ticket) => b.createdAt.localeCompare(a.createdAt);
  return {
    active: list.filter((t) => t.state !== "minted" && t.state !== "closed").sort(newest),
    invites: list.filter((t) => t.state === "minted").sort(newest),
    ended: list
      .filter((t) => t.state === "closed")
      .sort((a, b) => (b.endedAt ?? "").localeCompare(a.endedAt ?? "")),
  };
}
