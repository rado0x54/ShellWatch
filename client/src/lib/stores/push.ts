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
 * Sets the toggle from what the server holds, not just the browser: a local
 * subscription is re-sent to the server and counts as enabled only once the
 * server accepts it. A row lost server-side (DB reset, pruned) is re-created
 * on the way. Throws the server's refusal so the caller can surface it.
 */
export async function checkPushStatus(): Promise<void> {
  if (!pushSupported) return;
  const reg = await navigator.serviceWorker.ready;
  const sub = await reg.pushManager.getSubscription();
  if (!sub) {
    pushEnabled.set(false);
    return;
  }
  try {
    await registerWithServer(sub);
    pushEnabled.set(true);
  } catch (err) {
    pushEnabled.set(false);
    throw err;
  }
}

export async function subscribePush(): Promise<void> {
  pushLoading.set(true);
  try {
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
  } finally {
    pushLoading.set(false);
  }
}

export async function unsubscribePush(): Promise<void> {
  pushLoading.set(true);
  try {
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
  } finally {
    pushLoading.set(false);
  }
}
