// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { randomUUID } from "node:crypto";
import { count, eq } from "drizzle-orm";
import type { Config } from "../config/index.js";
import { coseToAuthorizedKeys } from "../webauthn/ssh-key-format.js";
import type { ShellWatchDB } from "./connection.js";
import { accounts, adminAccount, endpoints, webauthnCredentials } from "./schema.js";

/**
 * Seed the database with admin account, passkey, and endpoints from config.
 * SSH keys are auto-discovered by KeyDirectoryWatcher. Programmatic access is
 * no longer seeded here — agent credentials are minted as Hydra
 * OAuth clients self-register via mediated DCR + passkey login (#217).
 * Each section is independently idempotent.
 */
export interface SeedResult {
  seededAdminPasskey: boolean;
  seededAdminAccount: boolean;
  seededAdminId?: string;
}

export function seedFromConfig(db: ShellWatchDB, config: Config): SeedResult {
  const result: SeedResult = {
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
        name: "admin",
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

  // Seed admin passkeys (endpoints may reference them via keyRef → credentialId)
  for (const pk of config.seedAdminPasskeys) {
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
        publicKeyOpenSsh = coseToAuthorizedKeys(pubKeyBuf, config.security.rpId);
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
      db.insert(endpoints)
        .values({
          id: randomUUID(),
          accountId: adminId,
          label: ep.label,
          host: ep.address.host,
          port: ep.address.port,
          username: ep.address.username,
          agentForward: ep.agentForward,
          description: ep.description ?? null,
          enabled: true,
          createdAt: now,
          updatedAt: now,
        })
        .run();
    }
  }

  return result;
}
