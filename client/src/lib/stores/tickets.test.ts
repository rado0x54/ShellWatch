// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { afterEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_MINT_OPTIONS, mintTicket } from "./tickets.js";

describe("tickets store", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns a minted token even when the list refresh fails (it is shown only once)", async () => {
    const minted = { ticket: { id: "tk1" }, token: "tok-once" };
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify(minted), { status: 201 }))
      .mockRejectedValueOnce(new TypeError("network down"));
    await expect(mintTicket("ep1", { ...DEFAULT_MINT_OPTIONS })).resolves.toMatchObject({
      token: "tok-once",
    });
  });
});
