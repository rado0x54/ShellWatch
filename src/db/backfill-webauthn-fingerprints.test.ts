// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { eq } from "drizzle-orm";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fingerprintFromAuthorizedKeys } from "../webauthn/fingerprint.js";
import { backfillWebauthnFingerprints } from "./backfill-webauthn-fingerprints.js";
import { createDatabase, type DatabaseConnection } from "./connection.js";
import { runMigrations } from "./migrate.js";
import { CREDENTIAL_STATE } from "./repositories/credential-queries.js";
import { accounts, webauthnCredentials } from "./schema.js";

const KEY =
  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com AAAALndlYmF1dGgtZXhhbXBsZS1rZXktQQAAAAhuaXN0cDI1NgAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlsb2NhbGhvc3Q=";

describe("backfillWebauthnFingerprints", () => {
  let conn: DatabaseConnection;

  beforeEach(() => {
    // Use the actual migrate path. runMigrations calls backfill internally on
    // an empty DB (no-op), then the tests insert rows and call backfill again.
    conn = createDatabase(":memory:");
    runMigrations(conn.db);
    const now = new Date().toISOString();
    conn.db
      .insert(accounts)
      .values({ id: "acc-1", name: "Alice", createdAt: now, updatedAt: now })
      .run();
  });

  afterEach(() => conn.close());

  function insertCred(opts: {
    id: string;
    publicKeyOpenSsh: string | null;
    fingerprint?: string | null;
  }): void {
    conn.db
      .insert(webauthnCredentials)
      .values({
        id: opts.id,
        accountId: "acc-1",
        credentialId: `webauthn-${opts.id}`,
        publicKey: Buffer.alloc(0),
        label: opts.id,
        state: CREDENTIAL_STATE.active,
        revoked: false,
        publicKeyOpenSsh: opts.publicKeyOpenSsh,
        fingerprint: opts.fingerprint ?? null,
        createdAt: new Date().toISOString(),
      })
      .run();
  }

  function readFingerprint(id: string): string | null {
    const row = conn.db
      .select({ fingerprint: webauthnCredentials.fingerprint })
      .from(webauthnCredentials)
      .where(eq(webauthnCredentials.id, id))
      .get();
    return row?.fingerprint ?? null;
  }

  it("fills in fingerprints for rows with publicKeyOpenSsh set but fingerprint NULL", () => {
    insertCred({ id: "needs-backfill", publicKeyOpenSsh: KEY, fingerprint: null });
    const expected = fingerprintFromAuthorizedKeys(KEY);
    expect(expected).not.toBeNull();

    const result = backfillWebauthnFingerprints(conn.db);
    expect(result).toEqual({ updated: 1, skipped: 0 });
    expect(readFingerprint("needs-backfill")).toBe(expected);
  });

  it("leaves rows alone when fingerprint is already set", () => {
    insertCred({ id: "already-set", publicKeyOpenSsh: KEY, fingerprint: "SHA256:premade" });
    const result = backfillWebauthnFingerprints(conn.db);
    expect(result).toEqual({ updated: 0, skipped: 0 });
    expect(readFingerprint("already-set")).toBe("SHA256:premade");
  });

  it("leaves rows alone when publicKeyOpenSsh is NULL", () => {
    insertCred({ id: "no-ssh", publicKeyOpenSsh: null });
    const result = backfillWebauthnFingerprints(conn.db);
    expect(result).toEqual({ updated: 0, skipped: 0 });
    expect(readFingerprint("no-ssh")).toBeNull();
  });

  it("counts rows that fail to convert as skipped, leaves fingerprint NULL", () => {
    insertCred({ id: "garbage", publicKeyOpenSsh: "not-a-valid-ssh-key-string" });
    const result = backfillWebauthnFingerprints(conn.db);
    expect(result.skipped).toBeGreaterThanOrEqual(1);
    expect(readFingerprint("garbage")).toBeNull();
  });

  it("is idempotent — second run is a no-op", () => {
    insertCred({ id: "c1", publicKeyOpenSsh: KEY });
    expect(backfillWebauthnFingerprints(conn.db).updated).toBe(1);
    expect(backfillWebauthnFingerprints(conn.db).updated).toBe(0);
  });
});
