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
    const res = await fetch("/api/push/vapid-key");
    if (!res.ok) throw new Error("Push notifications not available on this server");
    const { publicKey } = await res.json();

    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: publicKey,
    });

    const subJson = sub.toJSON();
    await fetch("/api/push/subscribe", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        endpoint: subJson.endpoint,
        keys: subJson.keys,
      }),
    });

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
