// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3";
import { type BetterSQLite3Database, drizzle } from "drizzle-orm/better-sqlite3";
import * as schema from "./schema.js";

export type ShellWatchDB = BetterSQLite3Database<typeof schema>;

export interface DatabaseConnection {
  db: ShellWatchDB;
  close(): void;
}

/**
 * Create a database connection from a connection string.
 * Supported formats:
 *   - "sqlite:./data/shellwatch.db" (or just a file path)
 *   - ":memory:" (for tests)
 */
export function createDatabase(connectionString?: string): DatabaseConnection {
  const connStr = connectionString ?? process.env.SHELLWATCH_DB ?? "sqlite:./data/shellwatch.db";

  let dbPath: string;
  if (connStr === ":memory:") {
    dbPath = ":memory:";
  } else if (connStr.startsWith("sqlite:")) {
    dbPath = connStr.slice(7);
  } else if (!connStr.includes("://")) {
    dbPath = connStr;
  } else {
    throw new Error(`Unsupported database URL: ${connStr}. Only SQLite is supported for now.`);
  }

  if (dbPath !== ":memory:") {
    mkdirSync(dirname(dbPath), { recursive: true });
  }

  const sqlite = new Database(dbPath);
  sqlite.pragma("journal_mode = WAL");
  sqlite.pragma("foreign_keys = ON");

  const db = drizzle(sqlite, { schema });

  return {
    db,
    close() {
      sqlite.close();
    },
  };
}
