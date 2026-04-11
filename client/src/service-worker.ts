/// <reference types="@sveltejs/kit" />
/// <reference lib="webworker" />
declare const self: ServiceWorkerGlobalScope;

import { build, files, version } from "$service-worker";

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
  const url = new URL(event.request.url);

  // Skip non-GET, API, WebSocket, and MCP requests
  if (event.request.method !== "GET") return;
  if (url.pathname.startsWith("/api/")) return;
  if (url.pathname.startsWith("/ws")) return;
  if (url.pathname.startsWith("/mcp")) return;
  if (url.pathname === "/config.js") return;

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
    self.registration.showNotification(data.title || "ShellWatch", {
      body: data.body || "New sign request",
      icon: "/icon-192.png",
      badge: "/icon-64.png",
      tag: data.actionId, // Collapse duplicates for same action
      data: { deepLink: data.deepLink, actionId: data.actionId },
    }),
  );
});

// --- Notification click: focus existing tab or open deep link ---

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const deepLink: string | undefined = event.notification.data?.deepLink;
  if (!deepLink) return;

  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clientList) => {
      // Try to focus an existing ShellWatch tab
      for (const client of clientList) {
        if (new URL(client.url).origin === self.location.origin && "focus" in client) {
          client.navigate(deepLink);
          return client.focus();
        }
      }
      // No existing tab — open new one
      return self.clients.openWindow(deepLink);
    }),
  );
});
