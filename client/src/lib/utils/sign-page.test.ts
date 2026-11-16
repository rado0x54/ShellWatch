// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it } from "vitest";
import { createSignPageController, type SignActionLoad, type SignPageState } from "./sign-page.js";

interface A {
  id: string;
  status: string;
  context: { source: string };
}

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

const ok = (id: string, status = "pending"): SignActionLoad<A> => ({
  kind: "ok",
  action: { id, status, context: { source: "endpoint-auth" } },
  parentSessionTail: null,
});

describe("sign page controller (#308 §4)", () => {
  it("reloads and resets when the id changes (/sign/A -> /sign/B)", async () => {
    const states: SignPageState<A>[] = [];
    const ctrl = createSignPageController<A>(
      async (id) => ok(id, id === "A" ? "denied" : "pending"),
      (s) => states.push(s),
    );

    ctrl.load("A");
    await flush();
    // A reached an end state on the page.
    const a = states.at(-1)!;
    expect(a.action?.id).toBe("A");
    a.resultStatus = "expired";
    a.error = "boom";

    // "Details" on a new toast navigates to B: the page must show B.
    ctrl.load("B");
    const reset = states.at(-1)!;
    expect(reset).toMatchObject({
      actionId: "B",
      action: null,
      loading: true,
      error: null,
      resultStatus: null,
    });
    await flush();
    const b = states.at(-1)!;
    expect(b.action?.id).toBe("B");
    expect(b.action?.status).toBe("pending");
    expect(b.resultStatus).toBeNull();
    expect(b.loading).toBe(false);
    expect(ctrl.current()).toBe("B");
  });

  it("drops a late response for an id the page has left", async () => {
    const slowA = deferred<SignActionLoad<A>>();
    const states: SignPageState<A>[] = [];
    const ctrl = createSignPageController<A>(
      (id) => (id === "A" ? slowA.promise : Promise.resolve(ok("B"))),
      (s) => states.push(s),
    );
    ctrl.load("A");
    ctrl.load("B");
    await flush();
    slowA.resolve(ok("A"));
    await flush();
    expect(states.at(-1)!.action?.id).toBe("B");
  });

  it("navigating back to the same id loads it again", async () => {
    let calls = 0;
    const ctrl = createSignPageController<A>(
      async (id) => {
        calls++;
        return ok(id);
      },
      () => {},
    );
    ctrl.load("A");
    ctrl.load("B");
    ctrl.load("A");
    await flush();
    expect(calls).toBe(3);
  });

  it.each([
    [{ kind: "not-found" } as const, { error: "Action not found" }],
    [{ kind: "error" } as const, { error: "Failed to load action" }],
    [{ kind: "login" } as const, { needsLogin: true }],
  ])("maps %o", async (load, want) => {
    const states: SignPageState<A>[] = [];
    createSignPageController<A>(
      async () => load,
      (s) => states.push(s),
    ).load("X");
    await flush();
    expect(states.at(-1)).toMatchObject({ loading: false, action: null, ...want });
  });

  it("a thrown fetch is a load error", async () => {
    const states: SignPageState<A>[] = [];
    createSignPageController<A>(
      async () => {
        throw new Error("net");
      },
      (s) => states.push(s),
    ).load("X");
    await flush();
    expect(states.at(-1)).toMatchObject({ loading: false, error: "Failed to load action" });
  });
});
