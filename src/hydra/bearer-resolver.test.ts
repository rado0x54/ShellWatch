// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it, vi } from "vitest";
import type { HydraAdminClient } from "./admin-client.js";
import { createBearerResolver } from "./bearer-resolver.js";
import type { HydraIntrospection } from "./types.js";

// The resolver only calls admin.introspect — stub just that.
function resolverWith(
  introspect: (token: string) => Promise<HydraIntrospection>,
  opts: { cacheTtlMs?: number; now?: () => number } = {},
) {
  const admin = { introspect } as unknown as HydraAdminClient;
  return createBearerResolver({ admin, cacheTtlMs: opts.cacheTtlMs ?? 0, now: opts.now });
}

describe("bearer resolver", () => {
  it("resolves an active access token to a principal (sub = account, granted scope)", async () => {
    const resolve = resolverWith(async () => ({
      active: true,
      sub: "acct-1",
      scope: "openid offline_access ui",
      client_id: "shellwatch-web",
      token_use: "access_token",
    }));
    const p = await resolve("tok");
    expect(p?.accountId).toBe("acct-1");
    expect(p?.scopes).toContain("ui");
  });

  it("rejects an inactive token", async () => {
    const resolve = resolverWith(async () => ({ active: false }));
    expect(await resolve("dead")).toBeNull();
  });

  // Finding #1: a refresh token introspects active with the same sub+scope, but
  // must not be honored as a bearer (defends a refresh token leaked from
  // localStorage being replayed directly against the API).
  it("rejects a refresh token presented as a bearer (token_use=refresh_token)", async () => {
    const resolve = resolverWith(async () => ({
      active: true,
      sub: "acct-1",
      scope: "ui",
      token_use: "refresh_token",
    }));
    expect(await resolve("a-refresh-token")).toBeNull();
  });

  // Finding #2: introspection failure must fail CLOSED and must NOT be cached as
  // a negative result (a transient Hydra outage shouldn't lock the token out
  // for the whole TTL once Hydra recovers).
  it("fails closed when introspection throws, without caching the failure", async () => {
    let mode: "throw" | "ok" = "throw";
    const resolve = resolverWith(
      async () => {
        if (mode === "throw") throw new Error("hydra unreachable");
        return { active: true, sub: "acct-1", scope: "ui", token_use: "access_token" };
      },
      { cacheTtlMs: 60_000 },
    );
    expect(await resolve("tok")).toBeNull(); // transient failure → 401
    mode = "ok";
    expect((await resolve("tok"))?.accountId).toBe("acct-1"); // not negatively cached
  });

  // Finding #2: with a non-zero TTL, a revoked token keeps resolving until the
  // cache entry expires — the documented revocation-latency window — then
  // re-introspects and sees it's gone.
  it("serves a cached principal within the TTL, re-introspecting only after it", async () => {
    let t = 1_000_000;
    let active = true;
    const introspect = vi.fn(
      async (): Promise<HydraIntrospection> => ({
        active,
        sub: "acct-1",
        scope: "ui",
        token_use: "access_token",
      }),
    );
    const resolve = resolverWith(introspect, { cacheTtlMs: 60_000, now: () => t });

    expect((await resolve("tok"))?.accountId).toBe("acct-1");
    expect(introspect).toHaveBeenCalledTimes(1);

    // Revoked at Hydra, but still inside the cache window → still resolves.
    active = false;
    t += 30_000;
    expect((await resolve("tok"))?.accountId).toBe("acct-1");
    expect(introspect).toHaveBeenCalledTimes(1); // served from cache, no re-introspect

    // Past the TTL → re-introspects, now sees inactive → null.
    t += 31_000;
    expect(await resolve("tok")).toBeNull();
    expect(introspect).toHaveBeenCalledTimes(2);
  });

  // Invalid tokens must NOT be negatively cached — otherwise an attacker
  // spraying unique bad tokens could fill the cache and evict legit entries.
  it("does not cache invalid tokens, even with a non-zero TTL (re-introspects each time)", async () => {
    const introspect = vi.fn(async (): Promise<HydraIntrospection> => ({ active: false }));
    const resolve = resolverWith(introspect, { cacheTtlMs: 60_000 });
    expect(await resolve("bad")).toBeNull();
    expect(await resolve("bad")).toBeNull();
    expect(introspect).toHaveBeenCalledTimes(2);
  });

  it("does not cache when the TTL is zero (every call re-introspects)", async () => {
    const introspect = vi.fn(
      async (): Promise<HydraIntrospection> => ({
        active: true,
        sub: "acct-1",
        scope: "ui",
        token_use: "access_token",
      }),
    );
    const resolve = resolverWith(introspect, { cacheTtlMs: 0 });
    await resolve("tok");
    await resolve("tok");
    expect(introspect).toHaveBeenCalledTimes(2);
  });
});
