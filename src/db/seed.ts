import { createHash } from "node:crypto";
import { count, eq } from "drizzle-orm";
import type { Config } from "../config/index.js";
import { coseToAuthorizedKeys } from "../webauthn/ssh-key-format.js";
import type { ShellWatchDB } from "./connection.js";
import { apiKeys, endpoints, sshKeys, webauthnCredentials } from "./schema.js";

/**
 * Seed the database with admin passkey, endpoints, and API key from config.
 * SSH keys are auto-discovered by KeyDirectoryWatcher.
 * Each section is independently idempotent.
 */
export interface SeedResult {
  seededApiKey: boolean;
  apiKeyPrefix?: string;
  seededAdminPasskey: boolean;
}

export function seedFromConfig(db: ShellWatchDB, config: Config): SeedResult {
  const result: SeedResult = { seededApiKey: false, seededAdminPasskey: false };

  // Seed admin passkey first (endpoints may reference it via keyId)
  if (config.seedAdminPasskey) {
    const pk = config.seedAdminPasskey;
    const existing = db
      .select({ id: webauthnCredentials.id })
      .from(webauthnCredentials)
      .where(eq(webauthnCredentials.id, pk.id))
      .get();
    if (!existing) {
      const now = new Date().toISOString();
      const pubKeyBuf = Buffer.from(pk.publicKeyHex, "hex");
      const fingerprint = `SHA256:${createHash("sha256").update(pubKeyBuf).digest("base64url")}`;

      // Derive OpenSSH authorized_keys format from COSE key
      let publicKeyOpenSsh: string | null = null;
      try {
        publicKeyOpenSsh = coseToAuthorizedKeys(pubKeyBuf, "localhost", pk.label);
      } catch {
        // Non-fatal: key may not be convertible (e.g. unsupported algorithm)
      }

      db.insert(webauthnCredentials)
        .values({
          id: pk.id,
          credentialId: pk.credentialId,
          publicKey: pubKeyBuf,
          counter: pk.counter,
          transports: JSON.stringify(pk.transports),
          label: pk.label,
          publicKeyOpenSsh,
          createdAt: now,
        })
        .run();

      // Also register in ssh_keys so endpoints can reference this key via keyId
      db.insert(sshKeys)
        .values({
          id: pk.id,
          label: `${pk.label} (webauthn)`,
          type: "webauthn",
          publicKey: publicKeyOpenSsh ?? "",
          fingerprint,
          enabled: true,
          createdAt: now,
          updatedAt: now,
        })
        .run();

      result.seededAdminPasskey = true;
    }
  }

  // Seed endpoints on first run
  const endpointCount = db.select({ total: count() }).from(endpoints).get();
  if (!endpointCount || endpointCount.total === 0) {
    const now = new Date().toISOString();
    for (const server of config.seedServers) {
      // Only set keyId if the referenced key already exists in the DB
      // (file-based keys are discovered at runtime and linked later)
      let keyId: string | null = null;
      if (server.keyId) {
        const keyExists = db
          .select({ id: sshKeys.id })
          .from(sshKeys)
          .where(eq(sshKeys.id, server.keyId))
          .get();
        keyId = keyExists ? server.keyId : null;
      }

      db.insert(endpoints)
        .values({
          id: server.id,
          label: server.label,
          host: server.host,
          port: server.port,
          username: server.username,
          keyId,
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
      result.seededApiKey = true;
      result.apiKeyPrefix = config.seedApiKey.slice(0, 10);
    }
  }

  return result;
}
