// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { get } from "svelte/store";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { credentials, ReorderError, reorderPasskeys, type WebAuthnCredential } from "./webauthn.js";

const cred = (id: string, priority: number | null): WebAuthnCredential => ({
  id,
  credentialId: `cid-${id}`,
  label: id,
  algorithm: "ES256 (P-256)",
  fingerprint: null,
  authorizedKeysEntry: null,
  revoked: false,
  state: "active",
  createdAt: "2026-01-01T00:00:00.000Z",
  lastUsedAt: null,
  priority,
});

describe("reorderPasskeys (#308)", () => {
  beforeEach(() => credentials.set([cred("a", 0), cred("b", 1)]));
  afterEach(() => vi.restoreAllMocks());

  it("PUTs row ids and takes the server's list", async () => {
    const spy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ credentials: [cred("b", 0), cred("a", 1)], sshdConfig: "" })),
      );
    await reorderPasskeys(["b", "a"]);
    expect(spy.mock.calls[0][0]).toBe("/api/webauthn/credentials/order");
    const init = spy.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body as string)).toEqual({ ids: ["b", "a"] });
    expect(get(credentials).map((c) => c.id)).toEqual(["b", "a"]);
  });

  it("a 400 is a stale list and leaves the store unchanged", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(
        JSON.stringify({ error: "ids must list exactly the account's active passkeys" }),
        {
          status: 400,
        },
      ),
    );
    const err = await reorderPasskeys(["b"]).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ReorderError);
    expect((err as ReorderError).stale).toBe(true);
    expect(get(credentials).map((c) => c.id)).toEqual(["a", "b"]);
  });

  it("a 500 is not stale", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ error: "Internal server error" }), { status: 500 }),
    );
    const err = await reorderPasskeys(["b", "a"]).catch((e: unknown) => e);
    expect((err as ReorderError).stale).toBe(false);
  });
});
