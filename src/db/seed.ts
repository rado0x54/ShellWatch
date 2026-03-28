import { count } from "drizzle-orm";
import type { Config } from "../config/index.js";
import type { ShellWatchDB } from "./connection.js";
import { endpoints, sshKeys } from "./schema.js";

/**
 * Seed the database from YAML config on first run.
 * If tables already have data, this is a no-op.
 */
export function seedFromConfig(db: ShellWatchDB, config: Config): void {
  const keyCount = db.select({ total: count() }).from(sshKeys).get();
  if (keyCount && keyCount.total > 0) return;

  const now = new Date().toISOString();

  for (const key of config.keys) {
    db.insert(sshKeys)
      .values({
        id: key.id,
        label: key.label,
        type: "file",
        privateKeyPath: key.privateKeyPath,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      })
      .run();
  }

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
