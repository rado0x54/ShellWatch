// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/// <reference types="@sveltejs/kit" />
/// <reference lib="webworker" />
declare const self: ServiceWorkerGlobalScope;

import { build, files, version } from "$service-worker";
import { notificationTarget, serviceWorkerHandles, visibleAppWindow } from "$lib/guest/paths.js";

const CACHE_NAME = `shellwatch-${version}`;
const ASSETS = [...build, ...files];

// --- Install: precache app shell ---

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)));
  self.skipWaiting();
});

// --- Activate: clean old caches ---

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))),
      ),
  );
  self.clients.claim();
});

// --- Fetch: cache-first for assets, network for API ---

self.addEventListener("fetch", (event) => {
  // Skip non-GET, API, WebSocket and MCP requests — and the guest page's
  // navigation (#306), which always comes from the network: the owner's
  // installed worker must not serve it from the app shell.
  if (!serviceWorkerHandles(event.request)) return;

  event.respondWith(caches.match(event.request).then((cached) => cached || fetch(event.request)));
});

// --- Push: show notification for sign requests ---

interface PushPayload {
  title?: string;
  body?: string;
  actionId?: string;
  deepLink?: string;
  actionType?: string;
}

self.addEventListener("push", (event) => {
  const data: PushPayload = event.data?.json() ?? {};
  event.waitUntil(
    (async () => {
      // If a ShellWatch tab is already visible on this device, skip the push —
      // the in-page WebSocket toast will handle it. This prevents the triggering
      // device from getting a duplicate notification while other devices still do.
      // A guest window (/t, #306) has no owner WebSocket and shows no toast,
      // so it never counts as a ShellWatch tab here.
      const windows = await self.clients.matchAll({ type: "window" });
      if (visibleAppWindow(windows)) return;

      await self.registration.showNotification(data.title || "ShellWatch", {
        body: data.body || "New sign request",
        icon: "/icon-192.png",
        badge: "/icon-64.png",
        tag: data.actionId, // Collapse duplicates for same action
        data: { deepLink: data.deepLink, actionId: data.actionId },
      });
    })(),
  );
});

// --- Notification click: focus existing tab or open deep link ---

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const deepLink: string | undefined = event.notification.data?.deepLink;
  if (!deepLink) return;

  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clientList) => {
      // Focus an existing ShellWatch tab — never a guest window (/t, #306):
      // navigating it would turn the guest page into the owner's sign page.
      const target = notificationTarget(clientList, self.location.origin);
      if (target && "focus" in target) {
        target.navigate(deepLink);
        return target.focus();
      }
      // No existing tab — open new one
      return self.clients.openWindow(deepLink);
    }),
  );
});
