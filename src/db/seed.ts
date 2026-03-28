import { count } from "drizzle-orm";
import type { Config } from "../config/index.js";
import type { ScannedKey } from "../transport/key-scanner.js";
import type { ShellWatchDB } from "./connection.js";
import { endpoints, sshKeys } from "./schema.js";

/**
 * Seed the database from config and scanned keys on first run.
 * If tables already have data, this is a no-op.
 */
export function seedFromConfig(db: ShellWatchDB, config: Config, scannedKeys: ScannedKey[]): void {
  const keyCount = db.select({ total: count() }).from(sshKeys).get();
  if (keyCount && keyCount.total > 0) return;

  const now = new Date().toISOString();

  // Seed SSH keys from scanned files
  for (const key of scannedKeys) {
    db.insert(sshKeys)
      .values({
        id: key.filename.replace(/\.pem$/, ""),
        label: key.filename,
        type: "file",
        publicKey: key.publicKeyOpenSsh,
        fingerprint: key.fingerprint,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      })
      .run();
  }

  // Seed endpoints from config
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
