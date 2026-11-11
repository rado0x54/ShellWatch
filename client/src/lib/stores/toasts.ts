// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { get, writable } from "svelte/store";

import { notificationLink, type AppNotification } from "./notifications.js";

export type ToastVariant = "info" | "error" | "sign-request";

/** Host-key context on an endpoint-auth sign request (#241). */
export interface SignRequestHostKey {
  type: string;
  fingerprint: string;
  /** "new": approving this action also pins the presented host key. */
  status: "new" | "known";
}

interface SignRequestBase {
  actionId: string;
  deepLink: string;
  source: string;
  endpointLabel?: string;
  endpointAddress?: string;
  hostKey?: SignRequestHostKey;
}

export interface WebAuthnSignRequestAction extends SignRequestBase {
  actionType: "webauthn-sign";
  credentialId: string;
  challenge: string;
  rpId: string;
  passkeyLabel?: string;
}

export interface KeyApproveRequestAction extends SignRequestBase {
  actionType: "key-approve";
  keyLabel: string;
  keyFingerprint: string;
}

export type SignRequestAction = WebAuthnSignRequestAction | KeyApproveRequestAction;

export interface Toast {
  id: string;
  variant: ToastVariant;
  message: string;
  /** Present for sign-request toasts */
  action?: SignRequestAction;
  /** Auto-dismiss after this many ms (not used for sign-request) */
  dismissAfterMs?: number;
  /** Optional in-app link rendered after the message (e.g. host-key recovery). */
  link?: { href: string; label: string };
  /**
   * Full long-form text behind a "Details" affordance (#252). Toasts hold a
   * short headline only; anything that doesn't read at a glance — error
   * chains, fingerprints, raw server messages — goes here and is rendered
   * preformatted in a modal with room to breathe.
   */
  detail?: string;
  /**
   * The server notification this toast renders or references (#252). One
   * event can reach the client twice — the notification:new WS push and the
   * HTTP error that carries Error.notificationId — and this id is what keeps
   * it one toast, whichever path arrives first.
   */
  notificationId?: string;
}

let nextId = 0;

export const toasts = writable<Toast[]>([]);

export function addToast(toast: Omit<Toast, "id">): string {
  const id = `toast-${++nextId}`;
  toasts.update((t) => [...t, { ...toast, id }]);

  if (toast.dismissAfterMs) {
    setTimeout(() => removeToast(id), toast.dismissAfterMs);
  }

  return id;
}

export function removeToast(id: string): void {
  toasts.update((t) => t.filter((toast) => toast.id !== id));
}

/** Remove all toasts associated with a specific action ID */
export function clearAction(actionId: string): void {
  toasts.update((t) => t.filter((toast) => toast.action?.actionId !== actionId));
}

/** A toast message longer than this is summarized; the full text moves to
 * `detail` (#252). Roughly two lines at the toast's width. */
export const TOAST_SUMMARY_MAX = 160;

/**
 * Split a long message into a toast-sized summary + full-text detail (#252).
 * Short messages pass through unchanged. The summary breaks at a sentence or
 * clause boundary when one exists in range, else at a word boundary.
 */
export function splitLongMessage(message: string): { message: string; detail?: string } {
  if (message.length <= TOAST_SUMMARY_MAX) {
    return { message };
  }
  const head = message.slice(0, TOAST_SUMMARY_MAX);
  // Prefer the last sentence/clause boundary, then the last word boundary.
  let cut = Math.max(head.lastIndexOf(". "), head.lastIndexOf(": "), head.lastIndexOf("; "));
  if (cut < TOAST_SUMMARY_MAX / 3) {
    cut = head.lastIndexOf(" ");
  }
  if (cut < TOAST_SUMMARY_MAX / 3) {
    cut = TOAST_SUMMARY_MAX;
  }
  return { message: `${message.slice(0, cut).trimEnd()}…`, detail: message };
}

/**
 * Convenience: show an error toast (auto-dismiss after 10s). A long message
 * is summarized automatically with the full text behind "Details"; an
 * explicit detail skips the auto-split.
 */
export function toastError(message: string, detail?: string): string {
  const split = detail === undefined ? splitLongMessage(message) : { message, detail };
  return addToast({ variant: "error", ...split, dismissAfterMs: 10_000 });
}

/** Convenience: show an info toast (auto-dismiss after 3s) */
export function toastInfo(message: string): string {
  return addToast({ variant: "info", message, dismissAfterMs: 3000 });
}

/** Whether a toast for this server notification is already on screen. */
export function hasNotificationToast(notificationId: string): boolean {
  return get(toasts).some((t) => t.notificationId === notificationId);
}

/**
 * Render a server notification as a toast (#252). Dedupes by notification id:
 * if the HTTP-error fallback for the same event landed first, it is replaced
 * by this richer, typed rendering. Error-severity notifications stay until
 * dismissed — the event is already gone from the wire, this is its only
 * live surface.
 */
export function toastNotification(n: AppNotification): string {
  const existing = get(toasts).find((t) => t.notificationId === n.id);
  if (existing) {
    removeToast(existing.id);
  }
  return addToast({
    variant: n.severity === "info" ? "info" : "error",
    message: n.title,
    detail: n.detail ?? undefined,
    link: notificationLink(n),
    notificationId: n.id,
    dismissAfterMs: n.severity === "error" ? undefined : 10_000,
  });
}

/**
 * Error toast for a failed request (#252). When the failure references a
 * published notification (Error.notificationId), it dedupes against that
 * notification's toast; absent one (the WS alert was lost to a disconnect),
 * the HTTP error still surfaces — tagged with the id so a late push cannot
 * double-report.
 */
export function toastRequestError(message: string, notificationId?: string): string | null {
  if (notificationId && hasNotificationToast(notificationId)) {
    return null;
  }
  return addToast({
    variant: "error",
    ...splitLongMessage(message),
    notificationId,
    dismissAfterMs: 10_000,
  });
}
