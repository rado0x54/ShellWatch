// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createDatabase, type DatabaseConnection } from "../connection.js";
import { runMigrations } from "../migrate.js";
import { accounts, webauthnCredentials } from "../schema.js";
import {
  CREDENTIAL_STATE,
  findCredentialById,
  findCredentialsForAccount,
} from "./credential-queries.js";

const ACCT = "00000000-0000-0000-0000-000000000001";

describe("credential-queries — state gating", () => {
  let conn: DatabaseConnection;

  beforeEach(() => {
    conn = createDatabase(":memory:");
    runMigrations(conn.db);
    const now = new Date().toISOString();
    conn.db.insert(accounts).values({ id: ACCT, name: "A", createdAt: now, updatedAt: now }).run();
  });

  afterEach(() => conn.close());

  function insertCred(opts: {
    id: string;
    label: string;
    state?: "active" | "pending_confirmation";
    revoked?: boolean;
    publicKeyOpenSsh?: string | null;
  }) {
    conn.db
      .insert(webauthnCredentials)
      .values({
        id: opts.id,
        accountId: ACCT,
        credentialId: `webauthn-${opts.id}`,
        publicKey: Buffer.alloc(0),
        label: opts.label,
        state: opts.state ?? CREDENTIAL_STATE.active,
        revoked: opts.revoked ?? false,
        publicKeyOpenSsh: opts.publicKeyOpenSsh ?? null,
        createdAt: new Date().toISOString(),
      })
      .run();
  }

  it("findCredentialsForAccount returns only active, non-revoked rows", () => {
    insertCred({ id: "active-1", label: "active-1" });
    insertCred({ id: "active-2", label: "active-2" });
    insertCred({ id: "pending-1", label: "pending", state: "pending_confirmation" });
    insertCred({ id: "revoked-1", label: "revoked", revoked: true });

    const list = findCredentialsForAccount(conn.db, ACCT);
    const ids = list.map((c) => c.id).sort();
    expect(ids).toEqual(["active-1", "active-2"]);
  });

  it("findCredentialById refuses pending credentials", () => {
    insertCred({ id: "active-1", label: "active" });
    insertCred({ id: "pending-1", label: "pending", state: "pending_confirmation" });

    expect(findCredentialById(conn.db, "active-1")?.id).toBe("active-1");
    expect(findCredentialById(conn.db, "pending-1")).toBeNull();
  });

  it("findCredentialById refuses revoked credentials", () => {
    insertCred({ id: "revoked-1", label: "revoked", revoked: true });
    expect(findCredentialById(conn.db, "revoked-1")).toBeNull();
  });
});
