// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { apiFetch } from "../api.js";
import { writable } from "svelte/store";

export const pushSupported =
  typeof window !== "undefined" && "serviceWorker" in navigator && "PushManager" in window;

export const pushEnabled = writable(false);
export const pushLoading = writable(false);

/** Whether the server has VAPID configured (set from window.__VAPID_PUBLIC_KEY__). */
export function vapidAvailable(): boolean {
  return !!(window as unknown as { __VAPID_PUBLIC_KEY__?: string }).__VAPID_PUBLIC_KEY__;
}

/**
 * Hands a browser subscription to the server (an idempotent upsert). Throws
 * the server's error message when it refuses.
 */
async function registerWithServer(sub: PushSubscription): Promise<void> {
  const subJson = sub.toJSON();
  const res = await apiFetch("/api/push/subscribe", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ endpoint: subJson.endpoint, keys: subJson.keys }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || "Failed to register push subscription");
  }
}

/**
 * Every push operation (status check, subscribe, unsubscribe) takes a new
 * generation and holds pushLoading, which disables the toggle, so a user
 * action cannot start while a check is in flight. When operations still
 * overlap (e.g. leaving and re-entering the settings page mid-request), only
 * the newest one may clear pushLoading, and a superseded status check
 * discards its result instead of overwriting the newer state.
 */
let generation = 0;

async function exclusive<T>(op: (isCurrent: () => boolean) => Promise<T>): Promise<T> {
  const gen = ++generation;
  const isCurrent = () => gen === generation;
  pushLoading.set(true);
  try {
    return await op(isCurrent);
  } finally {
    if (isCurrent()) pushLoading.set(false);
  }
}

/**
 * Sets the toggle from what the server holds, not just the browser: a local
 * subscription is re-sent to the server and counts as enabled only once the
 * server accepts it. A row lost server-side (DB reset, pruned) is re-created
 * on the way. Throws the server's refusal so the caller can surface it; a
 * check superseded by a newer operation neither updates the toggle nor throws.
 */
export async function checkPushStatus(): Promise<void> {
  if (!pushSupported) return;
  await exclusive(async (isCurrent) => {
    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.getSubscription();
    if (!sub) {
      if (isCurrent()) pushEnabled.set(false);
      return;
    }
    try {
      await registerWithServer(sub);
      if (isCurrent()) pushEnabled.set(true);
    } catch (err) {
      if (!isCurrent()) return;
      pushEnabled.set(false);
      throw err;
    }
  });
}

export async function subscribePush(): Promise<void> {
  await exclusive(async () => {
    const publicKey = (window as unknown as { __VAPID_PUBLIC_KEY__?: string }).__VAPID_PUBLIC_KEY__;
    if (!publicKey) throw new Error("Push notifications not available on this server");

    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: publicKey,
    });

    try {
      await registerWithServer(sub);
    } catch (err) {
      // Server rejected — unsubscribe locally to stay in sync
      await sub.unsubscribe();
      throw err;
    }

    pushEnabled.set(true);
  });
}

export async function unsubscribePush(): Promise<void> {
  await exclusive(async () => {
    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.getSubscription();
    if (sub) {
      await apiFetch("/api/push/subscribe", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ endpoint: sub.endpoint }),
      });
      await sub.unsubscribe();
    }
    pushEnabled.set(false);
  });
}
