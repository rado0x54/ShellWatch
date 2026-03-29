import { count } from "drizzle-orm";
import type { Config } from "../config/index.js";
import type { ShellWatchDB } from "./connection.js";
import { endpoints } from "./schema.js";

/**
 * Seed the database with endpoints from config on first run.
 * SSH keys are auto-discovered by KeyDirectoryWatcher.
 * If endpoints already exist, this is a no-op.
 */
export function seedFromConfig(db: ShellWatchDB, config: Config): void {
  const endpointCount = db.select({ total: count() }).from(endpoints).get();
  if (endpointCount && endpointCount.total > 0) return;

  const now = new Date().toISOString();

  for (const server of config.servers) {
    db.insert(endpoints)
      .values({
        id: server.id,
        label: server.label,
        host: server.host,
        port: server.port,
        username: server.username,
        keyId: server.keyId,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      })
      .run();
  }
}
