// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { resolve } from "node:path";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import type { ShellWatchDB } from "./connection.js";

/**
 * Run pending database migrations.
 * Called at startup before any queries.
 */
export function runMigrations(db: ShellWatchDB): void {
  const migrationsFolder = resolve(import.meta.dirname, "../../drizzle");
  migrate(db, { migrationsFolder });
}
