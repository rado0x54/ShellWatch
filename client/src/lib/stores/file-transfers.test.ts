// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Transfer strip bookkeeping (#263): live frames, the attach snapshot and the
// audit history all feed one newest-first list.
import { describe, expect, it } from "vitest";
import {
  formatBytes,
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
