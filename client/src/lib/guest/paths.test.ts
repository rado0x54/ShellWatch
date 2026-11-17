// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it } from "vitest";
import {
  crossesGuestBoundary,
  isGuestPath,
  isUnauthPath,
  notificationTarget,
  serviceWorkerHandles,
  visibleAppWindow,
} from "./paths.js";

describe("guest page paths (#306)", () => {
  it("recognizes only /t as the guest page", () => {
    expect(isGuestPath("/t")).toBe(true);
    expect(isGuestPath("/t/")).toBe(true);
    for (const p of ["/", "/terminal", "/t/x", "/tickets", "/audit/tickets", "/session/t"]) {
      expect(isGuestPath(p)).toBe(false);
    }
  });

  it("treats /t as a public path, so the layout skips the authenticated bootstrap", () => {
    expect(isUnauthPath("/t")).toBe(true);
    expect(isUnauthPath("/register")).toBe(true);
    expect(isUnauthPath("/auth/callback")).toBe(true);
    expect(isUnauthPath("/passkey-invite/abc")).toBe(true);
    expect(isUnauthPath("/")).toBe(false);
    expect(isUnauthPath("/settings/endpoints")).toBe(false);
    expect(isUnauthPath("/audit/tickets")).toBe(false);
  });

  it("flags navigations that cross the guest boundary in either direction", () => {
    expect(crossesGuestBoundary("/", "/t")).toBe(true);
    expect(crossesGuestBoundary("/settings/endpoints", "/t")).toBe(true);
    expect(crossesGuestBoundary("/t", "/")).toBe(true);
    expect(crossesGuestBoundary("/t", "/sign/abc")).toBe(true);
    expect(crossesGuestBoundary("/", "/settings")).toBe(false);
    expect(crossesGuestBoundary("/t", "/t")).toBe(false);
  });
});

describe("service worker decisions (#306)", () => {
  const origin = "https://sw.example.com";
  const app = { url: `${origin}/settings`, visibilityState: "visible" };
  const guest = { url: `${origin}/t`, visibilityState: "visible" };

  it("serves the /t navigation from the network", () => {
    expect(serviceWorkerHandles({ method: "GET", mode: "navigate", url: `${origin}/t` })).toBe(
      false,
    );
    expect(serviceWorkerHandles({ method: "GET", mode: "navigate", url: `${origin}/` })).toBe(true);
    expect(
      serviceWorkerHandles({ method: "GET", mode: "no-cors", url: `${origin}/_app/x.js` }),
    ).toBe(true);
    for (const p of ["/api/tickets/redeem", "/ws/guest", "/ws", "/mcp", "/config.js"]) {
      expect(serviceWorkerHandles({ method: "GET", mode: "cors", url: origin + p })).toBe(false);
    }
    expect(serviceWorkerHandles({ method: "POST", mode: "cors", url: `${origin}/` })).toBe(false);
  });

  it("does not let a visible guest window suppress a push", () => {
    expect(visibleAppWindow([guest])).toBe(false);
    expect(visibleAppWindow([guest, app])).toBe(true);
    expect(visibleAppWindow([{ ...app, visibilityState: "hidden" }])).toBe(false);
  });

  it("never picks a guest window for a notification click", () => {
    expect(notificationTarget([guest], origin)).toBeNull();
    expect(notificationTarget([guest, app], origin)).toBe(app);
    expect(notificationTarget([{ url: "https://other.example/x" }], origin)).toBeNull();
  });
});
