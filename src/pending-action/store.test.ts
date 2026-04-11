import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SignResponse } from "../webauthn/ssh-agent.js";
import { PendingActionStore } from "./store.js";
import type { CreateActionParams } from "./types.js";

function makeParams(overrides?: Partial<CreateActionParams>): CreateActionParams {
  return {
    type: "webauthn-sign",
    accountId: "acc-1",
    context: { source: "agent-proxy", sourceIp: "127.0.0.1", apiKeyPrefix: "sw_test" },
    credentialId: "cred-1",
    challenge: "dGVzdC1jaGFsbGVuZ2U=",
    rpId: "localhost",
    passkeyLabel: "YubiKey",
    resolve: vi.fn(),
    reject: vi.fn(),
    ...overrides,
  };
}

const fakeResponse: SignResponse = {
  requestId: "unused",
  authenticatorData: Buffer.from("auth"),
  signature: Buffer.from("sig"),
  clientDataJSON: "{}",
};

describe("PendingActionStore", () => {
  let store: PendingActionStore;

  beforeEach(() => {
    vi.useFakeTimers();
    store = new PendingActionStore();
  });

  afterEach(() => {
    store.destroy();
    vi.useRealTimers();
  });

  it("creates an action with generated id and pending status", () => {
    const params = makeParams();
    const action = store.create(params);

    expect(action.id).toBeTruthy();
    expect(action.status).toBe("pending");
    expect(action.accountId).toBe("acc-1");
    expect(action.expiresAt).toBe(action.createdAt + 60_000);
  });

  it("retrieves a created action by id", () => {
    const action = store.create(makeParams());
    expect(store.get(action.id)).toBe(action);
  });

  it("returns undefined for unknown id", () => {
    expect(store.get("nonexistent")).toBeUndefined();
  });

  it("finds pending actions for an account", () => {
    const a1 = store.create(makeParams({ accountId: "acc-1" }));
    store.create(makeParams({ accountId: "acc-2" }));
    const a3 = store.create(makeParams({ accountId: "acc-1" }));

    const pending = store.findPendingForAccount("acc-1");
    expect(pending).toHaveLength(2);
    expect(pending.map((a) => a.id)).toContain(a1.id);
    expect(pending.map((a) => a.id)).toContain(a3.id);
  });

  it("resolves a pending action", () => {
    const resolve = vi.fn();
    const action = store.create(makeParams({ resolve }));

    const result = store.resolve(action.id, fakeResponse);
    expect(result).toBe(true);
    expect(action.status).toBe("completed");
    expect(resolve).toHaveBeenCalledWith(fakeResponse);
  });

  it("cannot resolve a non-pending action", () => {
    const action = store.create(makeParams());
    store.deny(action.id);
    expect(store.resolve(action.id, fakeResponse)).toBe(false);
  });

  it("denies a pending action", () => {
    const reject = vi.fn();
    const action = store.create(makeParams({ reject }));

    const result = store.deny(action.id);
    expect(result).toBe(true);
    expect(action.status).toBe("denied");
    expect(reject).toHaveBeenCalledWith(expect.any(Error));
  });

  it("expires actions after TTL via sweep", () => {
    const reject = vi.fn();
    const action = store.create(makeParams({ reject }));

    // Advance past the 60s TTL + sweep interval
    vi.advanceTimersByTime(70_000);

    expect(action.status).toBe("expired");
    expect(reject).toHaveBeenCalledWith(expect.any(Error));
  });

  it("does not include resolved actions in findPendingForAccount", () => {
    const action = store.create(makeParams());
    store.resolve(action.id, fakeResponse);

    expect(store.findPendingForAccount("acc-1")).toHaveLength(0);
  });

  it("destroy rejects all pending actions", () => {
    const reject1 = vi.fn();
    const reject2 = vi.fn();
    store.create(makeParams({ reject: reject1 }));
    store.create(makeParams({ reject: reject2 }));

    store.destroy();

    expect(reject1).toHaveBeenCalled();
    expect(reject2).toHaveBeenCalled();
  });
});
