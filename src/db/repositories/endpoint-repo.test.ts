// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { describe, expect, it } from "vitest";
import { InMemoryEndpointRepository } from "./endpoint-repo.js";

const ACCT_A = "acct-a";
const ACCT_B = "acct-b";

function seed() {
  return new InMemoryEndpointRepository([
    { id: "ep-a", accountId: ACCT_A, label: "A", host: "h", port: 22, username: "u" },
    { id: "ep-b", accountId: ACCT_B, label: "B", host: "h", port: 22, username: "u" },
  ]);
}

describe("InMemoryEndpointRepository scoping", () => {
  it("findAllForAccount returns only the caller's rows", async () => {
    const repo = seed();
    const a = await repo.findAllForAccount(ACCT_A);
    expect(a).toHaveLength(1);
    expect(a[0].id).toBe("ep-a");

    const b = await repo.findAllForAccount(ACCT_B);
    expect(b).toHaveLength(1);
    expect(b[0].id).toBe("ep-b");

    const empty = await repo.findAllForAccount("ghost");
    expect(empty).toEqual([]);
  });

  it("findByIdForAccount returns null when the row exists but belongs to another account", async () => {
    const repo = seed();
    expect(await repo.findByIdForAccount("ep-a", ACCT_A)).not.toBeNull();
    expect(await repo.findByIdForAccount("ep-a", ACCT_B)).toBeNull();
    expect(await repo.findByIdForAccount("ep-b", ACCT_A)).toBeNull();
    expect(await repo.findByIdForAccount("missing", ACCT_A)).toBeNull();
  });

  it("update only mutates rows owned by the caller", async () => {
    const repo = seed();
    await repo.update("ep-a", ACCT_B, { label: "hijack" }); // wrong owner
    const stillA = await repo.findByIdForAccount("ep-a", ACCT_A);
    expect(stillA?.label).toBe("A");
  });

  it("delete only removes rows owned by the caller", async () => {
    const repo = seed();
    await repo.delete("ep-a", ACCT_B); // wrong owner
    expect(await repo.findByIdForAccount("ep-a", ACCT_A)).not.toBeNull();
    await repo.delete("ep-a", ACCT_A);
    expect(await repo.findByIdForAccount("ep-a", ACCT_A)).toBeNull();
  });
});
