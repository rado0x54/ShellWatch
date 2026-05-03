// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { and, eq, lt, ne, sql } from "drizzle-orm";
import type { ShellWatchDB } from "./connection.js";
import { accounts, adminAccount, apiKeys, endpoints, webauthnCredentials } from "./schema.js";

const DEFAULT_INACTIVITY_DAYS = 90;
const CLEANUP_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Hard-delete accounts that have been inactive for longer than the configured threshold.
 * Admin accounts are exempt. Cascades to all owned data.
 */
export function cleanupInactiveAccounts(
  db: ShellWatchDB,
  inactivityDays = DEFAULT_INACTIVITY_DAYS,
): string[] {
  const cutoff = new Date(Date.now() - inactivityDays * 24 * 60 * 60 * 1000).toISOString();

  // Find the admin account ID to exclude
  const admin = db.select({ accountId: adminAccount.accountId }).from(adminAccount).get();
  const adminId = admin?.accountId;

  // Find expired accounts (not admin, coalesce lastUsedAt with createdAt for never-used accounts)
  const expired = db
    .select({ id: accounts.id })
    .from(accounts)
    .where(
      and(
        lt(sql`coalesce(${accounts.lastUsedAt}, ${accounts.createdAt})`, cutoff),
        adminId ? ne(accounts.id, adminId) : undefined,
      ),
    )
    .all();

  const deletedIds: string[] = [];

  for (const { id } of expired) {
    // Delete owned data (order matters for FK constraints).
    // audit_session_lifecycle has ON DELETE CASCADE; pushSubscriptions same.
    db.delete(webauthnCredentials).where(eq(webauthnCredentials.accountId, id)).run();
    db.delete(apiKeys).where(eq(apiKeys.accountId, id)).run();
    db.delete(endpoints).where(eq(endpoints.accountId, id)).run();
    db.delete(accounts).where(eq(accounts.id, id)).run();
    deletedIds.push(id);
  }

  return deletedIds;
}

/**
 * Start a periodic cleanup job. Returns a stop function.
 */
export function startCleanupJob(
  db: ShellWatchDB,
  inactivityDays = DEFAULT_INACTIVITY_DAYS,
  onCleanup?: (deletedIds: string[]) => void,
): () => void {
  const timer = setInterval(() => {
    const deleted = cleanupInactiveAccounts(db, inactivityDays);
    if (deleted.length > 0 && onCleanup) {
      onCleanup(deleted);
    }
  }, CLEANUP_INTERVAL_MS);
  timer.unref();

  return () => clearInterval(timer);
}
