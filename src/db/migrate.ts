// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { resolve } from "node:path";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import { backfillWebauthnFingerprints } from "./backfill-webauthn-fingerprints.js";
import type { ShellWatchDB } from "./connection.js";

/**
 * Run pending database migrations.
 * Called at startup before any queries.
 *
 * Also runs post-migration data backfills. Each backfill is idempotent and
 * cheap on the steady-state (zero-row scans once it's caught up), so we
 * always invoke them — there's no separate "this needs backfilling" flag.
 */
export function runMigrations(db: ShellWatchDB): void {
  const migrationsFolder = resolve(import.meta.dirname, "../../drizzle");
  migrate(db, { migrationsFolder });

  // 0009_webauthn_credentials_fingerprint introduced the column as nullable;
  // historical rows need their fingerprint computed from publicKeyOpenSsh.
  backfillWebauthnFingerprints(db);
}
