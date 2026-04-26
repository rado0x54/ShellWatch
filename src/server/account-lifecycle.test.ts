import { describe, expect, it, vi } from "vitest";
import { AccountLifecycle } from "./account-lifecycle.js";

describe("AccountLifecycle", () => {
  it("emitDeleted notifies every subscriber synchronously with the accountId", () => {
    const bus = new AccountLifecycle();
    const a = vi.fn();
    const b = vi.fn();
    bus.on("deleted", a);
    bus.on("deleted", b);

    bus.emitDeleted("acct-x");

    expect(a).toHaveBeenCalledWith({ accountId: "acct-x" });
    expect(b).toHaveBeenCalledWith({ accountId: "acct-x" });
  });

  it("emitting twice fires subscribers twice", () => {
    const bus = new AccountLifecycle();
    const handler = vi.fn();
    bus.on("deleted", handler);

    bus.emitDeleted("acct-1");
    bus.emitDeleted("acct-2");

    expect(handler).toHaveBeenCalledTimes(2);
    expect(handler).toHaveBeenNthCalledWith(1, { accountId: "acct-1" });
    expect(handler).toHaveBeenNthCalledWith(2, { accountId: "acct-2" });
  });
});
