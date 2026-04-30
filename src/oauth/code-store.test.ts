import { afterEach, describe, expect, it } from "vitest";
import { createAuthCodeStore, type AuthCodeStore } from "./code-store.js";

describe("auth code store", () => {
  let store: AuthCodeStore;

  afterEach(() => {
    store?.destroy();
  });

  const sampleEntry = {
    codeChallenge: "chal",
    codeChallengeMethod: "S256" as const,
    pending: { kind: "existing" as const, apiKey: "sw_test" },
    redirectUri: "http://127.0.0.1:55555/cb",
    clientId: "sw-client",
  };

  it("create returns a unique code that consume retrieves once", () => {
    store = createAuthCodeStore();
    const code = store.create(sampleEntry);
    expect(code).toMatch(/^[A-Za-z0-9_-]+$/);
    const first = store.consume(code);
    expect(first).not.toBeNull();
    expect(first?.pending).toEqual({ kind: "existing", apiKey: "sw_test" });
    // second consume must fail (single-use)
    expect(store.consume(code)).toBeNull();
  });

  it("consume of unknown code returns null", () => {
    store = createAuthCodeStore();
    expect(store.consume("nope")).toBeNull();
  });

  it("expired codes are rejected and evicted", () => {
    let t = 1_000_000;
    store = createAuthCodeStore({
      ttlMs: 100,
      sweepIntervalMs: 1_000_000, // effectively never during test
      now: () => t,
    });
    const code = store.create(sampleEntry);
    t += 200;
    expect(store.consume(code)).toBeNull();
  });

  it("generates distinct codes for concurrent creates", () => {
    store = createAuthCodeStore();
    const codes = new Set<string>();
    for (let i = 0; i < 50; i++) codes.add(store.create(sampleEntry));
    expect(codes.size).toBe(50);
    expect(store.size()).toBe(50);
  });
});
