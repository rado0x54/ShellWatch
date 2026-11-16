// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { get } from "svelte/store";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// pushSupported is computed at import time, so the browser push APIs are
// stubbed first and the module is imported fresh per test.
const fakeSub = {
  endpoint: "https://web.push.apple.com/x",
  unsubscribe: () => unsubscribeLocal(),
  toJSON: () => ({ endpoint: "https://web.push.apple.com/x", keys: { p256dh: "p", auth: "a" } }),
};
let localSub: typeof fakeSub | null;
const unsubscribeLocal = vi.fn(async () => {
  localSub = null;
  return true;
});

async function loadPush() {
  vi.resetModules();
  return import("./push.js");
}

describe("checkPushStatus", () => {
  beforeEach(() => {
    localSub = fakeSub;
    vi.stubGlobal("PushManager", function PushManager() {});
    vi.stubGlobal("window", globalThis); // node env: pushSupported checks `"PushManager" in window`
    vi.stubGlobal("__VAPID_PUBLIC_KEY__", "test-vapid-key");
    vi.stubGlobal("navigator", {
      serviceWorker: {
        ready: Promise.resolve({
          pushManager: {
            getSubscription: async () => localSub,
            subscribe: async () => (localSub = fakeSub),
          },
        }),
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

  it("holds pushLoading while the server confirms, so the toggle is disabled", async () => {
    let respond!: (r: Response) => void;
    vi.spyOn(globalThis, "fetch").mockReturnValueOnce(new Promise((r) => (respond = r)));
    const push = await loadPush();

    const check = push.checkPushStatus();
    await vi.waitFor(() => expect(get(push.pushLoading)).toBe(true));
    respond(new Response(JSON.stringify({ id: "s1" })));
    await check;

    expect(get(push.pushLoading)).toBe(false);
    expect(get(push.pushEnabled)).toBe(true);
  });

  it("runs an unsubscribe only after a pending check, so the check can't re-enable", async () => {
    let respondCheck!: (r: Response) => void;
    vi.spyOn(globalThis, "fetch").mockImplementation((_path, init) =>
      init?.method === "POST"
        ? new Promise((r) => (respondCheck = r))
        : Promise.resolve(new Response(JSON.stringify({ ok: true }))),
    );
    const push = await loadPush();
    push.pushEnabled.set(true); // stale value from an earlier visit

    const check = push.checkPushStatus();
    await vi.waitFor(() => expect(respondCheck).toBeDefined());
    const unsubscribe = push.unsubscribePush(); // queued behind the check
    respondCheck(new Response(JSON.stringify({ id: "s1" })));
    await Promise.all([check, unsubscribe]);

    expect(unsubscribeLocal).toHaveBeenCalled();
    expect(get(push.pushEnabled)).toBe(false);
    expect(get(push.pushLoading)).toBe(false);
  });

  it("keeps the toggle locked while an earlier subscribe is pending behind a newer check", async () => {
    const posts: Array<(r: Response) => void> = [];
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation((_path, init) =>
        init?.method === "POST"
          ? new Promise((r) => posts.push(r))
          : Promise.resolve(new Response(JSON.stringify({ ok: true }))),
      );
    localSub = null;
    const push = await loadPush();

    // Enable, leave and re-enter settings (a new check), then disable.
    const subscribe = push.subscribePush();
    await vi.waitFor(() => expect(posts).toHaveLength(1));
    const check = push.checkPushStatus();
    const unsubscribe = push.unsubscribePush();

    // The check waits for the subscribe; nothing has unlocked the toggle.
    await Promise.resolve();
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(get(push.pushLoading)).toBe(true);

    posts[0](new Response(JSON.stringify({ id: "s1" }))); // subscribe completes
    await vi.waitFor(() => expect(posts).toHaveLength(2));
    expect(get(push.pushLoading)).toBe(true);
    posts[1](new Response(JSON.stringify({ id: "s1" }))); // check completes
    await Promise.all([subscribe, check, unsubscribe]);

    // The user's last action (disable) wins.
    expect(get(push.pushEnabled)).toBe(false);
    expect(get(push.pushLoading)).toBe(false);
    expect(localSub).toBeNull();
  });
});
