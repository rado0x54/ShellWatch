// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { writable } from "svelte/store";

export const pushSupported =
  typeof window !== "undefined" && "serviceWorker" in navigator && "PushManager" in window;

export const pushEnabled = writable(false);
export const pushLoading = writable(false);

/** Whether the server has VAPID configured (set from window.__VAPID_PUBLIC_KEY__). */
export function vapidAvailable(): boolean {
  return !!(window as unknown as { __VAPID_PUBLIC_KEY__?: string }).__VAPID_PUBLIC_KEY__;
}

export async function checkPushStatus(): Promise<void> {
  if (!pushSupported) return;
  const reg = await navigator.serviceWorker.ready;
  const sub = await reg.pushManager.getSubscription();
  pushEnabled.set(sub !== null);
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

    const subJson = sub.toJSON();
    const res = await fetch("/api/push/subscribe", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        endpoint: subJson.endpoint,
        keys: subJson.keys,
      }),
    });

    if (!res.ok) {
      // Server rejected — unsubscribe locally to stay in sync
      await sub.unsubscribe();
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || "Failed to register push subscription");
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
      await fetch("/api/push/subscribe", {
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
