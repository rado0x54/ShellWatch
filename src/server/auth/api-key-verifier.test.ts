import { describe, expect, it, vi } from "vitest";
import { InMemoryApiKeyRepository, StubAccountRepository } from "../../db/index.js";
import { hashApiKey } from "./api-key-auth.js";
import { createApiKeyVerifier } from "./api-key-verifier.js";

async function seedKey(
  repo: InMemoryApiKeyRepository,
  raw: string,
  extras: Partial<{ id: string; accountId: string; scopes: string[] }> = {},
): Promise<void> {
  await repo.create({
    id: extras.id ?? "k1",
    accountId: extras.accountId ?? "acct_1",
    label: "Test",
    keyHash: hashApiKey(raw),
    keyPrefix: raw.slice(0, 7),
    scopes: extras.scopes ?? ["mcp", "agent"],
  });
}

describe("createApiKeyVerifier", () => {
  it("returns a Principal when the hashed key is known", async () => {
    const repo = new InMemoryApiKeyRepository();
    await seedKey(repo, "sw_test_abc123", { scopes: ["mcp", "agent"] });

    const verifier = createApiKeyVerifier(repo, new StubAccountRepository());
    const principal = await verifier.verify("sw_test_abc123");

    expect(principal).toEqual({
      accountId: "acct_1",
      scopes: ["mcp", "agent"],
      source: "api-key",
      tokenId: "k1",
    });
  });

  it("returns null for an unknown key", async () => {
    const verifier = createApiKeyVerifier(
      new InMemoryApiKeyRepository(),
      new StubAccountRepository(),
    );
    expect(await verifier.verify("sw_not_registered")).toBeNull();
  });

  it("returns null for a revoked key (repo filters disabled keys on findByHash)", async () => {
    const repo = new InMemoryApiKeyRepository();
    await seedKey(repo, "sw_revoke_me", { id: "k-revoke" });
    await repo.revoke("k-revoke");

    const verifier = createApiKeyVerifier(repo, new StubAccountRepository());
    expect(await verifier.verify("sw_revoke_me")).toBeNull();
  });

  it("returns null for an empty string without querying the repo", async () => {
    const repo = new InMemoryApiKeyRepository();
    const findSpy = vi.spyOn(repo, "findByHash");
    const verifier = createApiKeyVerifier(repo, new StubAccountRepository());
    expect(await verifier.verify("")).toBeNull();
    expect(findSpy).not.toHaveBeenCalled();
  });

  it("updates accounts.last_used_at on successful verification", async () => {
    const repo = new InMemoryApiKeyRepository();
    await seedKey(repo, "sw_touch_test", { id: "k-touch", accountId: "acct_touch" });
    const accountRepo = new StubAccountRepository();
    const touchSpy = vi.spyOn(accountRepo, "touchLastUsed");

    const verifier = createApiKeyVerifier(repo, accountRepo);
    await verifier.verify("sw_touch_test");

    expect(touchSpy).toHaveBeenCalledWith("acct_touch");
  });
});
