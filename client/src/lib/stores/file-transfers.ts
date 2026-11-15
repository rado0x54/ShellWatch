// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// File transfers (#263): what an MCP agent read, wrote or streamed through a
// session. One shape serves three sources — the audit log
// (GET /api/audit/file-transfers), the live `terminal:file` WebSocket frame,
// and the attach snapshot — so the strip above the terminal and the audit tab
// render the same thing.
import { apiFetch } from "../api.js";

export type TransferTier = "inline" | "link";
export type TransferDirection = "upload" | "download" | "list";

/** One row of the file-transfer audit log. */
export interface FileTransferRow {
  transferId: string;
  accountId: string;
  sessionId: string;
  endpointId: string;
  tier: TransferTier;
  direction: TransferDirection;
  path: string;
  /** Includes the audit-only `committing`; the WS frame reports it as `active`. */
  status: string;
  bytes: number;
  totalBytes: number | null;
  sha256: string | null;
  error: string | null;
  truncated: boolean | null;
  commitOutcome: string | null;
  cleanup: string | null;
  stagingPath: string | null;
  clientId: string | null;
  mcpClientName: string | null;
  mcpClientVersion: string | null;
  sourceIp: string | null;
  createdAt: string;
  updatedAt: string;
  finishedAt: string | null;
}

export interface FileTransferPage {
  rows: FileTransferRow[];
  nextCursor: string | null;
}

export interface FileTransferFilters {
  sessionId?: string;
  direction?: string;
  tier?: string;
  status?: string;
}

/** The `terminal:file` WebSocket frame (docs/api/websocket-protocol.md). */
export interface FileTransferEvent {
  type: "terminal:file";
  sessionId: string;
  transferId: string;
  tier: TransferTier;
  direction: TransferDirection;
  path: string;
  status: string;
  bytes: number;
  totalBytes?: number;
  sha256?: string;
  error?: string;
  truncated?: boolean;
  commitOutcome?: string;
  cleanup?: string;
  stagingPath?: string;
  mcpClientName: string;
}

/** What the transfer strip renders: the fields both sources share. */
export interface TransferView {
  transferId: string;
  tier: TransferTier;
  direction: TransferDirection;
  path: string;
  status: string;
  bytes: number;
  totalBytes: number | null;
  sha256: string | null;
  error: string | null;
  truncated: boolean | null;
  commitOutcome: string | null;
  cleanup: string | null;
  stagingPath: string | null;
  mcpClientName: string | null;
}

export async function fetchFileTransfersPage(
  filters: FileTransferFilters,
  cursor?: string,
  limit = 50,
): Promise<FileTransferPage> {
  const params = new URLSearchParams();
  if (filters.sessionId) params.set("sessionId", filters.sessionId);
  if (filters.direction) params.set("direction", filters.direction);
  if (filters.tier) params.set("tier", filters.tier);
  if (filters.status) params.set("status", filters.status);
  if (cursor) params.set("cursor", cursor);
  params.set("limit", String(limit));
  const res = await apiFetch(`/api/audit/file-transfers?${params}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || "Failed to fetch file-transfer log");
  }
  return res.json();
}

export function viewFromRow(r: FileTransferRow): TransferView {
  return {
    transferId: r.transferId,
    tier: r.tier,
    direction: r.direction,
    path: r.path,
    // The audit row's internal commit phase is still "in flight" to a viewer.
    status: r.status === "committing" ? "active" : r.status,
    bytes: r.bytes,
    totalBytes: r.totalBytes,
    sha256: r.sha256,
    error: r.error,
    truncated: r.truncated,
    commitOutcome: r.commitOutcome,
    cleanup: r.cleanup,
    stagingPath: r.stagingPath,
    mcpClientName: r.mcpClientName,
  };
}

export function viewFromEvent(e: FileTransferEvent): TransferView {
  return {
    transferId: e.transferId,
    tier: e.tier,
    direction: e.direction,
    path: e.path,
    status: e.status,
    bytes: e.bytes,
    totalBytes: e.totalBytes ?? null,
    sha256: e.sha256 ?? null,
    error: e.error ?? null,
    truncated: e.truncated ?? null,
    commitOutcome: e.commitOutcome ?? null,
    cleanup: e.cleanup ?? null,
    stagingPath: e.stagingPath ?? null,
    mcpClientName: e.mcpClientName || null,
  };
}

/** Transfers still in flight (the strip shows a progress bar for these). */
export function isUnfinished(status: string): boolean {
  return status === "pending" || status === "active" || status === "committing";
}

/**
 * Upsert a transfer into a newest-first list. A known transfer is updated in
 * place — it keeps its position, so a progress frame never reorders the list —
 * and a new one goes on top. The list is capped at `max`.
 *
 * A frame for a transfer that already finished is ignored unless it is itself
 * a finished frame (the late cleanup frame): the server orders its own frames,
 * but a history fetch can land between two of them.
 */
export function upsertTransfer(list: TransferView[], next: TransferView, max = 50): TransferView[] {
  const i = list.findIndex((t) => t.transferId === next.transferId);
  if (i === -1) return [next, ...list].slice(0, max);
  const current = list[i];
  if (!isUnfinished(current.status) && isUnfinished(next.status)) return list;
  const copy = list.slice();
  copy[i] = next;
  return copy;
}

/**
 * Merge a fetched history page under the live list: live entries win (they are
 * at least as fresh), history fills in what the socket never delivered.
 */
export function mergeHistory(
  live: TransferView[],
  history: TransferView[],
  max = 50,
): TransferView[] {
  const known = new Set(live.map((t) => t.transferId));
  return [...live, ...history.filter((t) => !known.has(t.transferId))].slice(0, max);
}

export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[u]}`;
}

/** Past/present-tense verb for a transfer, from the remote host's viewpoint. */
export function transferVerb(t: Pick<TransferView, "direction" | "status">): string {
  const running = isUnfinished(t.status);
  switch (t.direction) {
    case "upload":
      return running ? "writing" : "wrote";
    case "download":
      return running ? "reading" : "read";
    default:
      return running ? "listing" : "listed";
  }
}

/** Progress in [0, 1], or null when the total is unknown. */
export function transferProgress(t: Pick<TransferView, "bytes" | "totalBytes">): number | null {
  if (t.totalBytes === null || t.totalBytes <= 0) return null;
  return Math.max(0, Math.min(1, t.bytes / t.totalBytes));
}

/** Short digest for one-line display. */
export function shortSha(sha: string | null): string {
  return sha ? `${sha.slice(0, 12)}…` : "";
}
