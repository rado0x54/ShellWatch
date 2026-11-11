// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Live notification log races (#252 review): a page-one refetch must never
// erase a notification pushed while it was in flight.
import { describe, expect, it } from "vitest";
import { mergeLivePage, notificationLink, type AppNotification } from "./notifications.js";

function n(id: string): AppNotification {
  return {
    id,
    accountId: "acc",
    type: "session-connect-failed",
    severity: "warning",
    title: id,
    detail: null,
    payload: null,
    createdAt: "2026-01-01T00:00:00.000Z",
  };
}

describe("mergeLivePage", () => {
  it("keeps notifications pushed during the fetch on top of the fresh page", () => {
    const merged = mergeLivePage([n("live-2"), n("live-1")], [n("old-2"), n("old-1")]);
    expect(merged.map((r) => r.id)).toEqual(["live-2", "live-1", "old-2", "old-1"]);
  });

  it("drops pushed notifications the fetched page already contains", () => {
    // The server inserted live-1 before building the page AND pushed it: the
    // fetched copy wins, no duplicate row.
    const merged = mergeLivePage([n("live-1")], [n("live-1"), n("old-1")]);
    expect(merged.map((r) => r.id)).toEqual(["live-1", "old-1"]);
  });

  it("self-dedupes the pushed buffer and handles empty sides", () => {
    expect(mergeLivePage([n("a"), n("a")], []).map((r) => r.id)).toEqual(["a"]);
    expect(mergeLivePage([], [n("b")]).map((r) => r.id)).toEqual(["b"]);
    expect(mergeLivePage([], [])).toEqual([]);
  });
});

describe("notificationLink", () => {
  it("maps known kinds and leaves unknown kinds without an action", () => {
    expect(notificationLink({ ...n("x"), type: "host-key-mismatch" })).toEqual({
      href: "/settings/endpoints",
      label: "Review endpoint",
    });
    expect(notificationLink({ ...n("x"), type: "future-kind" })).toBeUndefined();
  });
});
