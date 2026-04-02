import { createHash } from "node:crypto";
import { count, eq } from "drizzle-orm";
import type { Config } from "../config/index.js";
import type { ShellWatchDB } from "./connection.js";
import { apiKeys, endpoints } from "./schema.js";

/**
 * Seed the database with endpoints and (optionally) an API key from config.
 * SSH keys are auto-discovered by KeyDirectoryWatcher.
 * Each section is independently idempotent.
 */
export function seedFromConfig(db: ShellWatchDB, config: Config): void {
  // Seed endpoints on first run
  const endpointCount = db.select({ total: count() }).from(endpoints).get();
  if (!endpointCount || endpointCount.total === 0) {
    const now = new Date().toISOString();
    for (const server of config.seedServers) {
      db.insert(endpoints)
        .values({
          id: server.id,
          label: server.label,
          host: server.host,
          port: server.port,
          username: server.username,
          enabled: true,
          createdAt: now,
          updatedAt: now,
        })
        .run();
    }
  }

  // Seed API key if configured and not already present
  if (config.seedApiKey) {
    const hash = createHash("sha256").update(config.seedApiKey).digest("hex");
    const existing = db
      .select({ id: apiKeys.id })
      .from(apiKeys)
      .where(eq(apiKeys.keyHash, hash))
      .get();
    if (!existing) {
      db.insert(apiKeys)
        .values({
          id: "seed-api-key",
          label: "Seeded from config",
          keyHash: hash,
          keyPrefix: config.seedApiKey.slice(0, 10),
          scopes: JSON.stringify(["mcp"]),
          endpoints: null,
          enabled: true,
          createdAt: new Date().toISOString(),
        })
        .run();
      console.log(`Seeded API key (prefix: ${config.seedApiKey.slice(0, 10)}…)`);
    }
  }
}
