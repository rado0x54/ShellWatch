// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Transfer strip bookkeeping (#263): live frames, the attach snapshot and the
// audit history all feed one newest-first list.
import { describe, expect, it } from "vitest";
import {
  formatBytes,
  loadSessionHistory,
  mergeHistory,
  transferProgress,
  transferVerb,
  upsertTransfer,
  viewFromEvent,
  viewFromRow,
  type FileTransferRow,
  type TransferView,
} from "./file-transfers.js";

function t(id: string, over: Partial<TransferView> = {}): TransferView {
  return {
    transferId: id,
    tier: "link",
    direction: "upload",
    path: "/srv/" + id,
    status: "active",
    bytes: 0,
    totalBytes: null,
    sha256: null,
    error: null,
    truncated: null,
    commitOutcome: null,
    cleanup: null,
    stagingPath: null,
    mcpClientName: "agent",
    ...over,
  };
}

describe("upsertTransfer", () => {
  it("puts a new transfer on top", () => {
    expect(upsertTransfer([t("a")], t("b")).map((x) => x.transferId)).toEqual(["b", "a"]);
  });

  it("updates a known transfer in place without reordering", () => {
    const list = upsertTransfer([t("b"), t("a")], t("a", { bytes: 512 }));
    expect(list.map((x) => x.transferId)).toEqual(["b", "a"]);
    expect(list[1].bytes).toBe(512);
  });

  it("never lets a stale in-flight frame resurrect a finished transfer", () => {
    const done = t("a", { status: "completed", bytes: 100 });
    expect(upsertTransfer([done], t("a", { status: "active", bytes: 40 }))).toEqual([done]);
  });

  it("accepts the late cleanup frame of a finished transfer", () => {
    const list = upsertTransfer(
      [t("a", { status: "failed", stagingPath: "/srv/.a.tmp" })],
      t("a", { status: "failed", cleanup: "failed", stagingPath: "/srv/.a.tmp" }),
    );
    expect(list[0].cleanup).toBe("failed");
  });

  it("caps the list", () => {
    expect(upsertTransfer([t("a"), t("b")], t("c"), 2).map((x) => x.transferId)).toEqual([
      "c",
      "a",
    ]);
  });
});

describe("mergeHistory", () => {
  it("keeps live entries and appends only unknown history", () => {
    const merged = mergeHistory(
      [t("live", { bytes: 9 })],
      [t("live", { bytes: 1, status: "pending" }), t("old", { status: "completed" })],
    );
    expect(merged.map((x) => x.transferId)).toEqual(["live", "old"]);
    expect(merged[0].bytes).toBe(9);
  });

  it("lets a finished log row replace a live entry stuck in flight", () => {
    // The transfer completed while the socket was down: the final frame never
    // arrived, so only the audit log knows.
    const merged = mergeHistory(
      [t("lost", { status: "active", bytes: 40 }), t("fresh", { status: "active", bytes: 7 })],
      [
        t("lost", { status: "completed", bytes: 100, sha256: "abc" }),
        t("fresh", { status: "pending", bytes: 0 }),
      ],
    );
    expect(merged.map((x) => x.transferId)).toEqual(["lost", "fresh"]);
    expect(merged[0]).toMatchObject({ status: "completed", bytes: 100, sha256: "abc" });
    // An in-flight row in the log never overrides the live entry.
    expect(merged[1]).toMatchObject({ status: "active", bytes: 7 });
  });

  it("never lets the log regress a finished live entry", () => {
    const merged = mergeHistory(
      [t("a", { status: "failed", cleanup: "failed" })],
      [t("a", { status: "failed" })],
    );
    expect(merged[0].cleanup).toBe("failed");
  });
});

describe("loadSessionHistory", () => {
  const row = (id: string, status: string) =>
    ({ ...t(id, { status }), sessionId: "sess_1" }) as unknown as FileTransferRow;

  it("reads one page when nothing is in flight", async () => {
    const calls: (string | undefined)[] = [];
    const views = await loadSessionHistory("sess_1", [], async (_f, cursor) => {
      calls.push(cursor);
      return { rows: [row("a", "completed")], nextCursor: "c1" };
    });
    expect(calls).toEqual([undefined]);
    expect(views.map((v) => v.transferId)).toEqual(["a"]);
  });

  it("follows pagination until every in-flight entry is accounted for", async () => {
    // "old" finished during an outage and sits behind a full page of newer rows.
    const pages: Record<string, { rows: FileTransferRow[]; nextCursor: string | null }> = {
      first: { rows: [row("n1", "completed"), row("n2", "completed")], nextCursor: "c1" },
      c1: { rows: [row("n3", "completed"), row("old", "completed")], nextCursor: "c2" },
      c2: { rows: [row("older", "completed")], nextCursor: null },
    };
    const calls: string[] = [];
    const views = await loadSessionHistory("sess_1", ["old"], async (filters, cursor, limit) => {
      expect(filters).toEqual({ sessionId: "sess_1" });
      expect(limit).toBe(50);
      calls.push(cursor ?? "first");
      return pages[cursor ?? "first"];
    });
    expect(calls).toEqual(["first", "c1"]); // stops once "old" was seen
    const merged = mergeHistory([t("old", { status: "active" })], views);
    expect(merged.find((v) => v.transferId === "old")?.status).toBe("completed");
  });

  it("stops at the end of the log and at the page cap", async () => {
    let calls = 0;
    await loadSessionHistory("sess_1", ["ghost"], async () => {
      calls++;
      return { rows: [], nextCursor: calls < 3 ? "more" : null };
    });
    expect(calls).toBe(3);

    calls = 0;
    await loadSessionHistory("sess_1", ["ghost"], async () => {
      calls++;
      return { rows: [], nextCursor: "always" };
    });
    expect(calls).toBe(10);
  });
});

describe("views", () => {
  it("reports the audit-only committing state as active", () => {
    const row = { ...t("a"), status: "committing" } as unknown as FileTransferRow;
    expect(viewFromRow(row).status).toBe("active");
  });

  it("normalizes absent frame fields to null", () => {
    const v = viewFromEvent({
      type: "terminal:file",
      sessionId: "sess_1",
      transferId: "xfer_1",
      tier: "inline",
      direction: "download",
      path: "/etc/hosts",
      status: "completed",
      bytes: 120,
      mcpClientName: "",
    });
    expect(v.totalBytes).toBeNull();
    expect(v.sha256).toBeNull();
    expect(v.mcpClientName).toBeNull();
  });
});

describe("formatting", () => {
  it("formats byte counts", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1023)).toBe("1023 B");
    expect(formatBytes(2150)).toBe("2.1 KB");
    expect(formatBytes(52428800)).toBe("50.0 MB");
    expect(formatBytes(1073741824)).toBe("1.0 GB");
    expect(formatBytes(-1)).toBe("—");
  });

  it("describes a transfer from the remote host's viewpoint", () => {
    expect(transferVerb({ direction: "upload", status: "completed" })).toBe("wrote");
    expect(transferVerb({ direction: "upload", status: "active" })).toBe("writing");
    expect(transferVerb({ direction: "download", status: "failed" })).toBe("read");
    expect(transferVerb({ direction: "list", status: "completed" })).toBe("listed");
  });

  it("computes progress only when the total is known", () => {
    expect(transferProgress({ bytes: 5, totalBytes: null })).toBeNull();
    expect(transferProgress({ bytes: 25, totalBytes: 100 })).toBe(0.25);
    expect(transferProgress({ bytes: 150, totalBytes: 100 })).toBe(1);
  });
});
