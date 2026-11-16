// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { get } from "svelte/store";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// pushSupported is computed at import time, so the browser push APIs are
// stubbed first and the module is imported fresh per test.
const fakeSub = {
  endpoint: "https://web.push.apple.com/x",
  toJSON: () => ({ endpoint: "https://web.push.apple.com/x", keys: { p256dh: "p", auth: "a" } }),
};
let localSub: typeof fakeSub | null;

async function loadPush() {
  vi.resetModules();
  return import("./push.js");
}

describe("checkPushStatus", () => {
  beforeEach(() => {
    localSub = fakeSub;
    vi.stubGlobal("PushManager", function PushManager() {});
    vi.stubGlobal("window", globalThis); // node env: pushSupported checks `"PushManager" in window`
    vi.stubGlobal("navigator", {
      serviceWorker: {
        ready: Promise.resolve({ pushManager: { getSubscription: async () => localSub } }),
      },
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("is off without a local subscription and does not call the server", async () => {
    localSub = null;
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const push = await loadPush();

    await push.checkPushStatus();

    expect(get(push.pushEnabled)).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("re-sends the local subscription and is on once the server accepts it", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: "s1" })));
    const push = await loadPush();

    await push.checkPushStatus();

    expect(get(push.pushEnabled)).toBe(true);
    const [path, init] = fetchSpy.mock.calls[0];
    expect(path).toBe("/api/push/subscribe");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual(fakeSub.toJSON());
  });

  it("is off and surfaces the error when the server refuses", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(
        JSON.stringify({ error: "endpoint already registered to a different account" }),
        {
          status: 409,
        },
      ),
    );
    const push = await loadPush();
    push.pushEnabled.set(true);

    await expect(push.checkPushStatus()).rejects.toThrow("different account");
    expect(get(push.pushEnabled)).toBe(false);
  });
});
