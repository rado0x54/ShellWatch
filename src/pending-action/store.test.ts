// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SignResponse } from "../webauthn/ssh-agent.js";
import { PendingActionStore } from "./store.js";
import type { KeyApproveAction, WebAuthnSignAction } from "./types.js";

type WebAuthnCreateParams = Omit<WebAuthnSignAction, "id" | "status" | "createdAt" | "expiresAt">;
type KeyApproveCreateParams = Omit<KeyApproveAction, "id" | "status" | "createdAt" | "expiresAt">;

function makeWebAuthnParams(overrides?: Partial<WebAuthnCreateParams>): WebAuthnCreateParams {
  return {
    type: "webauthn-sign",
    accountId: "acc-1",
    context: {
      source: "agent-proxy",
      sourceIp: "127.0.0.1",
    },
    credentialId: "cred-1",
    challenge: "dGVzdC1jaGFsbGVuZ2U=",
    rpId: "localhost",
    passkeyLabel: "YubiKey",
    userVerification: "required",
    resolve: vi.fn(),
    reject: vi.fn(),
    ...overrides,
  };
}

function makeKeyApproveParams(overrides?: Partial<KeyApproveCreateParams>): KeyApproveCreateParams {
  return {
    type: "key-approve",
    accountId: "acc-1",
    context: {
      source: "endpoint-auth",
      endpointLabel: "Prod",
      endpointAddress: "user@host:22",
      trigger: { kind: "ui", sourceIp: "127.0.0.1" },
    },
    keyLabel: "Test Key",
    keyFingerprint: "SHA256:abc123",
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
    const action = store.create(makeWebAuthnParams());

    expect(action.id).toBeTruthy();
    expect(action.status).toBe("pending");
    expect(action.accountId).toBe("acc-1");
    expect(action.expiresAt).toBe(action.createdAt + 60_000);
  });

  it("retrieves a created action by id", () => {
    const action = store.create(makeWebAuthnParams());
    expect(store.get(action.id)).toBe(action);
  });

  it("returns undefined for unknown id", () => {
    expect(store.get("nonexistent")).toBeUndefined();
  });

  it("finds pending actions for an account", () => {
    const a1 = store.create(makeWebAuthnParams({ accountId: "acc-1" }));
    store.create(makeWebAuthnParams({ accountId: "acc-2" }));
    const a3 = store.create(makeKeyApproveParams({ accountId: "acc-1" }));

    const pending = store.findPendingForAccount("acc-1");
    expect(pending).toHaveLength(2);
    expect(pending.map((a) => a.id)).toContain(a1.id);
    expect(pending.map((a) => a.id)).toContain(a3.id);
  });

  it("resolves a webauthn-sign action with response", () => {
    const resolve = vi.fn();
    const action = store.create(makeWebAuthnParams({ resolve }));

    const result = store.resolve(action.id, fakeResponse);
    expect(result).toBe(true);
    expect(action.status).toBe("completed");
    expect(resolve).toHaveBeenCalledWith(fakeResponse);
  });

  it("resolves a key-approve action without response", () => {
    const resolve = vi.fn();
    const action = store.create(makeKeyApproveParams({ resolve }));

    const result = store.resolve(action.id);
    expect(result).toBe(true);
    expect(action.status).toBe("completed");
    expect(resolve).toHaveBeenCalled();
  });

  it("rejects resolve of webauthn-sign without response", () => {
    const resolve = vi.fn();
    const action = store.create(makeWebAuthnParams({ resolve }));

    const result = store.resolve(action.id);
    expect(result).toBe(false);
    expect(action.status).toBe("pending");
    expect(resolve).not.toHaveBeenCalled();
  });

  it("cannot resolve a non-pending action", () => {
    const action = store.create(makeWebAuthnParams());
    store.deny(action.id);
    expect(store.resolve(action.id, fakeResponse)).toBe(false);
  });

  it("denies a pending action", () => {
    const reject = vi.fn();
    const action = store.create(makeWebAuthnParams({ reject }));

    const result = store.deny(action.id);
    expect(result).toBe(true);
    expect(action.status).toBe("denied");
    expect(reject).toHaveBeenCalledWith(expect.any(Error));
  });

  it("denies a key-approve action", () => {
    const reject = vi.fn();
    const action = store.create(makeKeyApproveParams({ reject }));

    store.deny(action.id);
    expect(action.status).toBe("denied");
    expect(reject).toHaveBeenCalledWith(expect.any(Error));
  });

  it("expires actions after TTL via sweep", () => {
    const reject = vi.fn();
    const action = store.create(makeWebAuthnParams({ reject }));

    vi.advanceTimersByTime(70_000);

    expect(action.status).toBe("expired");
    expect(reject).toHaveBeenCalledWith(expect.any(Error));
  });

  it("does not include resolved actions in findPendingForAccount", () => {
    const action = store.create(makeWebAuthnParams());
    store.resolve(action.id, fakeResponse);

    expect(store.findPendingForAccount("acc-1")).toHaveLength(0);
  });

  it("destroy rejects all pending actions", () => {
    const reject1 = vi.fn();
    const reject2 = vi.fn();
    store.create(makeWebAuthnParams({ reject: reject1 }));
    store.create(makeKeyApproveParams({ reject: reject2 }));

    store.destroy();

    expect(reject1).toHaveBeenCalled();
    expect(reject2).toHaveBeenCalled();
  });
});
