import { count } from "drizzle-orm";
import type { Config } from "../config/index.js";
import type { ShellWatchDB } from "./connection.js";
import { endpoints } from "./schema.js";

/**
 * Seed the endpoints table from YAML config on first run.
 * If the table already has data, this is a no-op (DB is the source of truth).
 */
export function seedEndpoints(db: ShellWatchDB, config: Config): void {
  const result = db.select({ total: count() }).from(endpoints).get();
  if (result && result.total > 0) return;

  const now = new Date().toISOString();

  for (const server of config.servers) {
    db.insert(endpoints)
      .values({
        id: server.id,
        label: server.label,
        host: server.host,
        port: server.port,
        username: server.username,
        privateKeyPath: server.privateKeyPath,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      })
      .run();
  }
}
