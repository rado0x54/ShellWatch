// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { get } from "svelte/store";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_MINT_OPTIONS,
  endReasonLabel,
  fetchTickets,
  groupTickets,
  mintTicket,
  revokeTicket,
  ticketsClockOffset,
  type Ticket,
  type TicketState,
} from "./tickets.js";

function ticket(
  id: string,
  state: TicketState,
  createdAt: string,
  endedAt: string | null = null,
): Ticket {
  return {
    id,
    endpointId: "ep",
    label: "",
    createdAt,
    expiresAt: createdAt,
    redeemTtlSeconds: 300,
    lifetimeSeconds: 900,
    reasonRequired: true,
    agentForward: false,
    state,
    guest: null,
    endedAt,
    endReason: endedAt ? "client.guest" : null,
  };
}

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

  it("groups the guest-access page: active, unused links, recently ended (newest first)", () => {
    const g = groupTickets([
      ticket("m1", "minted", "2026-01-01T00:00:01Z"),
      ticket("o1", "open", "2026-01-01T00:00:02Z"),
      ticket("p1", "pending", "2026-01-01T00:00:03Z"),
      ticket("m2", "minted", "2026-01-01T00:00:04Z"),
      ticket("c1", "closed", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z"),
      ticket("c2", "closed", "2026-01-01T00:00:00Z", "2026-01-01T00:02:00Z"),
    ]);
    expect(g.active.map((t) => t.id)).toEqual(["p1", "o1"]);
    expect(g.invites.map((t) => t.id)).toEqual(["m2", "m1"]);
    expect(g.ended.map((t) => t.id)).toEqual(["c2", "c1"]);
  });

  it("names end reasons for people and falls back to the raw reason", () => {
    expect(endReasonLabel("ticket-revoked")).toBe("revoked");
    expect(endReasonLabel("client.guest")).toBe("ended by the guest");
    expect(endReasonLabel("something-new")).toBe("something-new");
    expect(endReasonLabel(null)).toBe("unknown");
  });

  it("reports a revoke of an already ended ticket as ended, not as an error", async () => {
    const list = () => new Response(JSON.stringify({ tickets: [] }));
    vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ status: "revoked" }), { status: 200 }))
      .mockResolvedValueOnce(list())
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "Ticket already ended" }), { status: 409 }),
      )
      .mockResolvedValueOnce(list());
    expect(await revokeTicket("a")).toBe("revoked");
    expect(await revokeTicket("b")).toBe("ended");
  });

  it("takes the server clock offset from the list response's Date header", async () => {
    const serverNow = Date.now() + 120_000;
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ tickets: [] }), {
        headers: { Date: new Date(serverNow).toUTCString() },
      }),
    );
    await fetchTickets();
    // The Date header has 1 s resolution.
    expect(Math.abs(get(ticketsClockOffset) - 120_000)).toBeLessThan(2000);
  });
});
