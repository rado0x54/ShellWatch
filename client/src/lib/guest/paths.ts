// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Route classification shared by the root layout and the service worker
 * (#306). The guest page `/t` is the one-time access page an untrusted
 * browser opens; it must never share a document with the authenticated app.
 */

/** The guest page path (`/t#<token>`). */
export const GUEST_PATH = "/t";

/** Whether a pathname is the guest page. */
export function isGuestPath(path: string): boolean {
  return path === GUEST_PATH || path === `${GUEST_PATH}/`;
}

/**
 * Public, no-token routes that render fullscreen (no sidebar) and skip the
 * authenticated bootstrap (token refresh, OAuth redirect, `/ws`, fetches).
 */
export function isUnauthPath(path: string): boolean {
  return (
    isGuestPath(path) ||
    path.endsWith("/register") ||
    path.includes("/passkey-invite/") ||
    path.includes("/auth/callback")
  );
}

/**
 * Whether a navigation from one path to another crosses the guest-page
 * boundary in either direction. Such a navigation must be a full document
 * load: the root layout's bootstrap runs once per document, so a client-side
 * move into `/t` would keep the owner's WebSocket and stores alive, and a move
 * out of it would skip the bootstrap entirely.
 */
export function crossesGuestBoundary(from: string, to: string): boolean {
  return isGuestPath(from) !== isGuestPath(to);
}

/** The window fields the service worker's decisions read. */
export interface WindowLike {
  url: string;
  visibilityState?: string;
}

function windowPath(w: WindowLike): string | null {
  try {
    return new URL(w.url).pathname;
  } catch {
    return null;
  }
}

/** Whether a window shows the guest page. */
export function isGuestWindow(w: WindowLike): boolean {
  const path = windowPath(w);
  return path !== null && isGuestPath(path);
}

/**
 * Whether a push should stay silent because a ShellWatch tab is visible on
 * this device (its in-page toast covers the request). A guest window has no
 * owner WebSocket and shows no toast, so it never counts.
 */
export function visibleAppWindow(windows: readonly WindowLike[]): boolean {
  return windows.some((w) => w.visibilityState === "visible" && !isGuestWindow(w));
}

/**
 * The window a notification click may navigate to its deep link: the first
 * same-origin app window — never a guest window, which would turn the guest
 * page into the owner's sign page. null -> open a new window.
 */
export function notificationTarget<W extends WindowLike>(
  windows: readonly W[],
  origin: string,
): W | null {
  for (const w of windows) {
    if (isGuestWindow(w)) continue;
    try {
      if (new URL(w.url).origin === origin) return w;
    } catch {
      // unparsable client URL: skip
    }
  }
  return null;
}

/**
 * Whether the service worker answers a GET from its cache. The guest page's
 * navigation always goes to the network.
 */
export function serviceWorkerHandles(req: { method: string; mode: string; url: string }): boolean {
  if (req.method !== "GET") return false;
  const url = new URL(req.url);
  const p = url.pathname;
  if (p.startsWith("/api/") || p.startsWith("/ws") || p.startsWith("/mcp") || p === "/config.js") {
    return false;
  }
  return !(req.mode === "navigate" && isGuestPath(p));
}
