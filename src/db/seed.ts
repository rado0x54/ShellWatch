import { createHash, randomUUID } from "node:crypto";
import { count, eq } from "drizzle-orm";
import type { Config } from "../config/index.js";
import { coseToAuthorizedKeys } from "../webauthn/ssh-key-format.js";
import type { ShellWatchDB } from "./connection.js";
import { accounts, adminAccount, apiKeys, endpoints, webauthnCredentials } from "./schema.js";

/**
 * Seed the database with admin account, passkey, endpoints, and API key from config.
 * SSH keys are auto-discovered by KeyDirectoryWatcher.
 * Each section is independently idempotent.
 */
export interface SeedResult {
  seededApiKey: boolean;
  apiKeyPrefix?: string;
  seededAdminPasskey: boolean;
  seededAdminAccount: boolean;
  seededAdminId?: string;
}

export function seedFromConfig(db: ShellWatchDB, config: Config): SeedResult {
  const result: SeedResult = {
    seededApiKey: false,
    seededAdminPasskey: false,
    seededAdminAccount: false,
  };

  // Seed admin account if no accounts exist yet
  const accountCount = db.select({ total: count() }).from(accounts).get();
  let adminId: string;
  if (!accountCount || accountCount.total === 0) {
    adminId = randomUUID();
    const now = new Date().toISOString();
    db.insert(accounts)
      .values({
        id: adminId,
        name: "Admin",
        type: "human",
        enabled: true,
        maxSessions: 5,
        lastUsedAt: now,
        createdAt: now,
        updatedAt: now,
      })
      .run();
    // Designate as admin via singleton table
    db.insert(adminAccount).values({ singleton: 1, accountId: adminId }).run();
    result.seededAdminAccount = true;
    result.seededAdminId = adminId;
  } else {
    // Find existing admin account for linking
    const admin = db.select({ accountId: adminAccount.accountId }).from(adminAccount).get();
    if (!admin) throw new Error("No admin account found — database is in an invalid state");
    adminId = admin.accountId;
  }

  // Seed admin passkey (endpoints may reference it via keyRef → credentialId)
  if (config.seedAdminPasskey) {
    const pk = config.seedAdminPasskey;
    const existing = db
      .select({ id: webauthnCredentials.id })
      .from(webauthnCredentials)
      .where(eq(webauthnCredentials.credentialId, pk.credentialId))
      .get();
    if (!existing) {
      const id = randomUUID();
      const now = new Date().toISOString();
      const pubKeyBuf = Buffer.from(pk.publicKeyHex, "hex");

      // Derive OpenSSH authorized_keys format from COSE key
      let publicKeyOpenSsh: string | null = null;
      try {
        publicKeyOpenSsh = coseToAuthorizedKeys(pubKeyBuf, "localhost", pk.label);
      } catch {
        // Non-fatal: key may not be convertible (e.g. unsupported algorithm)
      }

      db.insert(webauthnCredentials)
        .values({
          id,
          accountId: adminId,
          credentialId: pk.credentialId,
          publicKey: pubKeyBuf,
          counter: pk.counter,
          transports: JSON.stringify(pk.transports),
          label: pk.label,
          publicKeyOpenSsh,
          createdAt: now,
        })
        .run();

      result.seededAdminPasskey = true;
    }
  }

  // Seed endpoints on first run
  const endpointCount = db.select({ total: count() }).from(endpoints).get();
  if (!endpointCount || endpointCount.total === 0) {
    const now = new Date().toISOString();
    for (const ep of config.seedAdminEndpoints) {
      // Resolve passkeyCredentialRef to a webauthn_credentials.id
      let passkeyId: string | null = null;
      if (ep.passkeyCredentialRef) {
        const cred = db
          .select({ id: webauthnCredentials.id })
          .from(webauthnCredentials)
          .where(eq(webauthnCredentials.credentialId, ep.passkeyCredentialRef))
          .get();
        passkeyId = cred?.id ?? null;
      }

      db.insert(endpoints)
        .values({
          id: randomUUID(),
          accountId: adminId,
          label: ep.label,
          host: ep.address.host,
          port: ep.address.port,
          username: ep.address.username,
          passkeyId,
          enabled: true,
          createdAt: now,
          updatedAt: now,
        })
        .run();
    }
  }

  // Seed API key if configured and not already present
  if (config.seedAdminApiKey) {
    const hash = createHash("sha256").update(config.seedAdminApiKey).digest("hex");
    const existing = db
      .select({ id: apiKeys.id })
      .from(apiKeys)
      .where(eq(apiKeys.keyHash, hash))
      .get();
    if (!existing) {
      db.insert(apiKeys)
        .values({
          id: randomUUID(),
          accountId: adminId,
          label: "Seeded from config",
          keyHash: hash,
          keyPrefix: config.seedAdminApiKey.slice(0, 10),
          scopes: JSON.stringify(["mcp"]),
          endpoints: null,
          enabled: true,
          createdAt: new Date().toISOString(),
        })
        .run();
      result.seededApiKey = true;
      result.apiKeyPrefix = config.seedAdminApiKey.slice(0, 10);
    }
  }

  return result;
}
