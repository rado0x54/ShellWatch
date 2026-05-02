import { and, desc, eq, lt, or } from "drizzle-orm";
import type { ShellWatchDB } from "../db/connection.js";
import { auditSessionLifecycle } from "../db/schema.js";

export interface SessionLifecycleRow {
  sessionId: string;
  accountId: string;
  endpointId: string;
  source: string;
  status: string;
  createdAt: string;
  closedAt: string | null;
  durationMs: number | null;
  sourceIp: string | null;
  mcpReason: string | null;
  mcpClientName: string | null;
  mcpClientVersion: string | null;
  apiKeyLabel: string | null;
  apiKeyPrefix: string | null;
  clientHostname: string | null;
  clientOs: string | null;
  clientVersion: string | null;
  closeReason: string | null;
}

export interface SessionLifecycleInsert {
  sessionId: string;
  accountId: string;
  endpointId: string;
  source: string;
  status: string;
  createdAt: string;
  sourceIp?: string;
  mcpReason?: string;
  mcpClientName?: string;
  mcpClientVersion?: string;
  apiKeyLabel?: string;
  apiKeyPrefix?: string;
}

export interface SessionLifecycleClose {
  sessionId: string;
  status: string;
  closedAt: string;
  durationMs: number;
  closeReason?: string;
}

export interface SessionLifecycleFilters {
  endpointId?: string;
}

export interface SessionLifecyclePage {
  rows: SessionLifecycleRow[];
  /** Cursor for the next page; null if this was the final page. */
  nextCursor: string | null;
}

const PAGE_LIMIT_DEFAULT = 50;
const PAGE_LIMIT_MAX = 500;

/**
 * Account-scoped repository for the session-lifecycle audit log.
 *
 * No cross-account read methods are exposed by design — there are no callers
 * that legitimately need to enumerate sessions across tenants. See #136.
 */
export interface SessionLifecycleRepository {
  insertOpen(row: SessionLifecycleInsert): void;
  recordClose(row: SessionLifecycleClose): void;
  list(
    accountId: string,
    filters: SessionLifecycleFilters,
    paging: { cursor?: string; limit?: number },
  ): SessionLifecyclePage;
  findOne(sessionId: string, accountId: string): SessionLifecycleRow | null;
}

export class DrizzleSessionLifecycleRepository implements SessionLifecycleRepository {
  constructor(private db: ShellWatchDB) {}

  insertOpen(row: SessionLifecycleInsert): void {
    this.db
      .insert(auditSessionLifecycle)
      .values({
        sessionId: row.sessionId,
        accountId: row.accountId,
        endpointId: row.endpointId,
        source: row.source,
        status: row.status,
        createdAt: row.createdAt,
        sourceIp: row.sourceIp ?? null,
        mcpReason: row.mcpReason ?? null,
        mcpClientName: row.mcpClientName ?? null,
        mcpClientVersion: row.mcpClientVersion ?? null,
        apiKeyLabel: row.apiKeyLabel ?? null,
        apiKeyPrefix: row.apiKeyPrefix ?? null,
      })
      .run();
  }

  recordClose(row: SessionLifecycleClose): void {
    this.db
      .update(auditSessionLifecycle)
      .set({
        status: row.status,
        closedAt: row.closedAt,
        durationMs: row.durationMs,
        closeReason: row.closeReason ?? null,
      })
      .where(eq(auditSessionLifecycle.sessionId, row.sessionId))
      .run();
  }

  list(
    accountId: string,
    filters: SessionLifecycleFilters,
    paging: { cursor?: string; limit?: number },
  ): SessionLifecyclePage {
    const limit = clampLimit(paging.limit);

    // Cursor encodes the last-seen (created_at, session_id) tuple so we can
    // page deterministically even when many rows share a created_at timestamp.
    const cursor = decodeCursor(paging.cursor);

    const conditions = [eq(auditSessionLifecycle.accountId, accountId)];
    if (filters.endpointId) {
      conditions.push(eq(auditSessionLifecycle.endpointId, filters.endpointId));
    }
    if (cursor) {
      // (created_at, session_id) < (cursor.createdAt, cursor.sessionId) under DESC ordering.
      conditions.push(
        or(
          lt(auditSessionLifecycle.createdAt, cursor.createdAt),
          and(
            eq(auditSessionLifecycle.createdAt, cursor.createdAt),
            lt(auditSessionLifecycle.sessionId, cursor.sessionId),
          ),
        )!,
      );
    }

    const rows = this.db
      .select()
      .from(auditSessionLifecycle)
      .where(and(...conditions))
      .orderBy(desc(auditSessionLifecycle.createdAt), desc(auditSessionLifecycle.sessionId))
      .limit(limit + 1)
      .all() as SessionLifecycleRow[];

    const hasMore = rows.length > limit;
    const trimmed = hasMore ? rows.slice(0, limit) : rows;
    const last = trimmed[trimmed.length - 1];
    const nextCursor =
      hasMore && last
        ? encodeCursor({ createdAt: last.createdAt, sessionId: last.sessionId })
        : null;

    return { rows: trimmed, nextCursor };
  }

  findOne(sessionId: string, accountId: string): SessionLifecycleRow | null {
    const row = this.db
      .select()
      .from(auditSessionLifecycle)
      .where(
        and(
          eq(auditSessionLifecycle.sessionId, sessionId),
          eq(auditSessionLifecycle.accountId, accountId),
        ),
      )
      .get();
    return (row as SessionLifecycleRow | undefined) ?? null;
  }
}

function clampLimit(raw: number | undefined): number {
  if (raw === undefined || !Number.isFinite(raw)) return PAGE_LIMIT_DEFAULT;
  const n = Math.floor(raw);
  if (n <= 0) return PAGE_LIMIT_DEFAULT;
  return Math.min(n, PAGE_LIMIT_MAX);
}

interface Cursor {
  createdAt: string;
  sessionId: string;
}

function encodeCursor(c: Cursor): string {
  return Buffer.from(JSON.stringify(c), "utf8").toString("base64url");
}

function decodeCursor(raw: string | undefined): Cursor | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(Buffer.from(raw, "base64url").toString("utf8")) as Cursor;
    if (typeof parsed.createdAt !== "string" || typeof parsed.sessionId !== "string") return null;
    return parsed;
  } catch {
    // Treat malformed cursors as "no cursor" — the caller's filters still
    // narrow the page, so a bad cursor just rewinds to the first page.
    return null;
  }
}
