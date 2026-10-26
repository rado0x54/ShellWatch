// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Account notification log (#252): server-originated events the user must not
 * miss, persisted server-side as an append-only audit surface (Audit →
 * Notifications) and pushed live as `notification:new`. This module owns the
 * wire type, the log fetch, and the typed per-kind action links — client
 * behavior derives from `type` + `payload`, never from text.
 */
import { apiFetch } from "../api.js";

export type NotificationSeverity = "info" | "warning" | "error";

export interface AppNotification {
  id: string;
  accountId: string;
  type: string;
  severity: NotificationSeverity;
  /** Toast-sized headline. */
  title: string;
  /** Long-form preformatted text behind a Details view. */
  detail: string | null;
  /** Type-specific structured data (see docs/api/websocket-protocol.md). */
  payload: Record<string, unknown> | null;
  createdAt: string;
}

export interface NotificationPage {
  rows: AppNotification[];
  nextCursor: string | null;
}

export async function fetchNotifications(cursor?: string, limit = 50): Promise<NotificationPage> {
  const params = new URLSearchParams();
  if (cursor) params.set("cursor", cursor);
  params.set("limit", String(limit));
  const res = await apiFetch(`/api/audit/notifications?${params}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || "Failed to fetch notifications");
  }
  return res.json();
}

/**
 * The typed action a notification kind offers (#252). Unknown kinds get none:
 * they still render title/detail, so an older client degrades gracefully when
 * the server grows new producers.
 */
export function notificationLink(n: AppNotification): { href: string; label: string } | undefined {
  switch (n.type) {
    case "host-key-mismatch":
      return { href: "/settings/endpoints", label: "Review endpoint" };
    default:
      return undefined;
  }
}
