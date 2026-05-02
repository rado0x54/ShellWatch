import { and, desc, eq, gte, inArray, isNull, lt, lte, or } from "drizzle-orm";
import type { ShellWatchDB } from "../db/connection.js";
import { auditSigningRequests } from "../db/schema.js";

export interface SigningRequestRow {
  id: string;
  accountId: string;
  type: string;
  source: string;
  createdAt: string;
  resolvedAt: string | null;
  outcome: string | null;
  latencyMs: number | null;
  sourceIp: string | null;
  endpointLabel: string | null;
  endpointAddress: string | null;
  sessionId: string | null;
  mcpReason: string | null;
  mcpClientName: string | null;
  mcpClientVersion: string | null;
  apiKeyLabel: string | null;
  apiKeyPrefix: string | null;
  clientHostname: string | null;
  clientOs: string | null;
  clientVersion: string | null;
  credentialId: string | null;
  passkeyLabel: string | null;
  userVerification: string | null;
  keyLabel: string | null;
  keyFingerprint: string | null;
  cancelReason: string | null;
}

export interface SigningRequestInsert {
  id: string;
  accountId: string;
  type: string;
  source: string;
  createdAt: string;
  sourceIp?: string;
  endpointLabel?: string;
  endpointAddress?: string;
  sessionId?: string;
  mcpReason?: string;
  mcpClientName?: string;
  mcpClientVersion?: string;
  apiKeyLabel?: string;
  apiKeyPrefix?: string;
  clientHostname?: string;
  clientOs?: string;
  clientVersion?: string;
  credentialId?: string;
  passkeyLabel?: string;
  userVerification?: string;
  keyLabel?: string;
  keyFingerprint?: string;
}

export interface SigningRequestResolution {
  id: string;
  outcome: string;
  resolvedAt: string;
  latencyMs: number;
  cancelReason?: string;
}

export interface SigningRequestFilters {
  source?: string | string[];
  type?: string | string[];
  outcome?: string | string[];
  credentialId?: string;
  sessionId?: string;
  /** Inclusive lower bound on created_at (ISO-8601). */
  from?: string;
  /** Inclusive upper bound on created_at (ISO-8601). */
  to?: string;
}

export interface SigningRequestPage {
  rows: SigningRequestRow[];
  /** Cursor for the next page; null if this was the final page. */
  nextCursor: string | null;
}

const PAGE_LIMIT_DEFAULT = 50;
const PAGE_LIMIT_MAX = 500;

/**
 * Account-scoped repository for the signing-request audit log (#186).
 *
 * No cross-account read methods are exposed by design; rows are scoped to
 * `account_id` at the DB layer (FK with cascade delete on account removal).
 */
export interface SigningRequestsRepository {
  insertCreated(row: SigningRequestInsert): void;
  recordResolution(row: SigningRequestResolution): void;
  list(
    accountId: string,
    filters: SigningRequestFilters,
    paging: { cursor?: string; limit?: number },
  ): SigningRequestPage;
  getById(accountId: string, id: string): SigningRequestRow | null;
}

export class DrizzleSigningRequestsRepository implements SigningRequestsRepository {
  constructor(private db: ShellWatchDB) {}

  insertCreated(row: SigningRequestInsert): void {
    this.db
      .insert(auditSigningRequests)
      .values({
        id: row.id,
        accountId: row.accountId,
        type: row.type,
        source: row.source,
        createdAt: row.createdAt,
        sourceIp: row.sourceIp ?? null,
        endpointLabel: row.endpointLabel ?? null,
        endpointAddress: row.endpointAddress ?? null,
        sessionId: row.sessionId ?? null,
        mcpReason: row.mcpReason ?? null,
        mcpClientName: row.mcpClientName ?? null,
        mcpClientVersion: row.mcpClientVersion ?? null,
        apiKeyLabel: row.apiKeyLabel ?? null,
        apiKeyPrefix: row.apiKeyPrefix ?? null,
        clientHostname: row.clientHostname ?? null,
        clientOs: row.clientOs ?? null,
        clientVersion: row.clientVersion ?? null,
        credentialId: row.credentialId ?? null,
        passkeyLabel: row.passkeyLabel ?? null,
        userVerification: row.userVerification ?? null,
        keyLabel: row.keyLabel ?? null,
        keyFingerprint: row.keyFingerprint ?? null,
      })
      .run();
  }

  recordResolution(row: SigningRequestResolution): void {
    // Idempotent on resolved_at: if a row has already been resolved (e.g. a
    // late cancel arriving after expiry) keep the first terminal write.
    this.db
      .update(auditSigningRequests)
      .set({
        outcome: row.outcome,
        resolvedAt: row.resolvedAt,
        latencyMs: row.latencyMs,
        cancelReason: row.cancelReason ?? null,
      })
      .where(and(eq(auditSigningRequests.id, row.id), isNull(auditSigningRequests.resolvedAt)))
      .run();
  }

  list(
    accountId: string,
    filters: SigningRequestFilters,
    paging: { cursor?: string; limit?: number },
  ): SigningRequestPage {
    const limit = clampLimit(paging.limit);
    const cursor = decodeCursor(paging.cursor);

    const conditions = [eq(auditSigningRequests.accountId, accountId)];
    pushInOrEq(conditions, auditSigningRequests.source, filters.source);
    pushInOrEq(conditions, auditSigningRequests.type, filters.type);
    pushInOrEq(conditions, auditSigningRequests.outcome, filters.outcome);
    if (filters.credentialId) {
      conditions.push(eq(auditSigningRequests.credentialId, filters.credentialId));
    }
    if (filters.sessionId) {
      conditions.push(eq(auditSigningRequests.sessionId, filters.sessionId));
    }
    if (filters.from) {
      conditions.push(gte(auditSigningRequests.createdAt, filters.from));
    }
    if (filters.to) {
      conditions.push(lte(auditSigningRequests.createdAt, filters.to));
    }
    if (cursor) {
      conditions.push(
        or(
          lt(auditSigningRequests.createdAt, cursor.createdAt),
          and(
            eq(auditSigningRequests.createdAt, cursor.createdAt),
            lt(auditSigningRequests.id, cursor.id),
          ),
        )!,
      );
    }

    const rows = this.db
      .select()
      .from(auditSigningRequests)
      .where(and(...conditions))
      .orderBy(desc(auditSigningRequests.createdAt), desc(auditSigningRequests.id))
      .limit(limit + 1)
      .all() as SigningRequestRow[];

    const hasMore = rows.length > limit;
    const trimmed = hasMore ? rows.slice(0, limit) : rows;
    const last = trimmed[trimmed.length - 1];
    const nextCursor =
      hasMore && last ? encodeCursor({ createdAt: last.createdAt, id: last.id }) : null;

    return { rows: trimmed, nextCursor };
  }

  getById(accountId: string, id: string): SigningRequestRow | null {
    const row = this.db
      .select()
      .from(auditSigningRequests)
      .where(and(eq(auditSigningRequests.accountId, accountId), eq(auditSigningRequests.id, id)))
      .get();
    return (row as SigningRequestRow | undefined) ?? null;
  }
}

function pushInOrEq<T>(
  conditions: unknown[],
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  column: any,
  value: T | T[] | undefined,
): void {
  if (value === undefined) return;
  if (Array.isArray(value)) {
    if (value.length === 0) return;
    conditions.push(inArray(column, value));
  } else {
    conditions.push(eq(column, value));
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
  id: string;
}

function encodeCursor(c: Cursor): string {
  return Buffer.from(JSON.stringify(c), "utf8").toString("base64url");
}

function decodeCursor(raw: string | undefined): Cursor | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(Buffer.from(raw, "base64url").toString("utf8")) as Cursor;
    if (typeof parsed.createdAt !== "string" || typeof parsed.id !== "string") return null;
    return parsed;
  } catch {
    return null;
  }
}
