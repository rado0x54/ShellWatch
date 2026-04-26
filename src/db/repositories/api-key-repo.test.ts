import { describe, expect, it } from "vitest";
import { InMemoryApiKeyRepository } from "./api-key-repo.js";

const ACCT_A = "acct-a";
const ACCT_B = "acct-b";

async function seed() {
  const repo = new InMemoryApiKeyRepository();
  await repo.create({
    id: "key-a",
    accountId: ACCT_A,
    label: "A's key",
    keyHash: "hash-a",
    keyPrefix: "sw_aaaa",
    scopes: ["mcp"],
  });
  await repo.create({
    id: "key-b",
    accountId: ACCT_B,
    label: "B's key",
    keyHash: "hash-b",
    keyPrefix: "sw_bbbb",
    scopes: ["mcp"],
  });
  return repo;
}

describe("InMemoryApiKeyRepository scoping", () => {
  it("findAllForAccount returns only the caller's rows", async () => {
    const repo = await seed();
    const a = await repo.findAllForAccount(ACCT_A);
    expect(a).toHaveLength(1);
    expect(a[0].id).toBe("key-a");

    const b = await repo.findAllForAccount(ACCT_B);
    expect(b).toHaveLength(1);
    expect(b[0].id).toBe("key-b");

    const empty = await repo.findAllForAccount("ghost");
    expect(empty).toEqual([]);
  });

  it("revokeForAccount returns false when the row belongs to another account and does not flip enabled", async () => {
    const repo = await seed();
    const result = await repo.revokeForAccount("key-a", ACCT_B);
    expect(result).toBe(false);

    const stillEnabled = (await repo.findAllForAccount(ACCT_A))[0];
    expect(stillEnabled.enabled).toBe(true);
  });

  it("revokeForAccount returns true and flips enabled when called by the owner", async () => {
    const repo = await seed();
    const result = await repo.revokeForAccount("key-a", ACCT_A);
    expect(result).toBe(true);

    const revoked = (await repo.findAllForAccount(ACCT_A))[0];
    expect(revoked.enabled).toBe(false);
  });

  it("findByHash filters out revoked keys (auth must reject)", async () => {
    const repo = await seed();
    expect(await repo.findByHash("hash-a")).not.toBeNull();
    await repo.revokeForAccount("key-a", ACCT_A);
    expect(await repo.findByHash("hash-a")).toBeNull();
  });

  it("findAllForAccount preserves revoked keys (UI must show them)", async () => {
    const repo = await seed();
    await repo.revokeForAccount("key-a", ACCT_A);
    const rows = await repo.findAllForAccount(ACCT_A);
    expect(rows).toHaveLength(1);
    expect(rows[0].enabled).toBe(false);
  });
});
