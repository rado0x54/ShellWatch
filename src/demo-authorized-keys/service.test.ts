// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createDatabase, type DatabaseConnection } from "../db/connection.js";
import { runMigrations } from "../db/migrate.js";
import { CREDENTIAL_STATE } from "../db/repositories/credential-queries.js";
import { accounts, webauthnCredentials } from "../db/schema.js";
import { fingerprintFromAuthorizedKeys } from "../webauthn/fingerprint.js";
import { createDemoAuthorizedKeysService } from "./service.js";

// Two minimal authorized_keys-style lines that exercise the
// fingerprint/type-extraction path. Body bytes don't need to be a real key —
// fingerprintFromAuthorizedKeys + toSkPublicKeyBlob just hash the wire blob.
const KEY_A =
  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com AAAALndlYmF1dGgtZXhhbXBsZS1rZXktQQAAAAhuaXN0cDI1NgAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlsb2NhbGhvc3Q=";
const KEY_B =
  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com AAAALndlYmF1dGgtZXhhbXBsZS1rZXktQgAAAAhuaXN0cDI1NgAAACABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAAlsb2NhbGhvc3Q=";

function fingerprintOf(line: string): string {
  const fp = fingerprintFromAuthorizedKeys(line);
  if (!fp) throw new Error("test setup: cannot compute fingerprint");
  return fp;
}

describe("DemoAuthorizedKeysService", () => {
  let conn: DatabaseConnection;
  let now: number;

  beforeEach(() => {
    conn = createDatabase(":memory:");
    runMigrations(conn.db);
    now = 0;
    const ts = new Date().toISOString();
    conn.db
      .insert(accounts)
      .values([
        { id: "acc-1", name: "Alice", createdAt: ts, updatedAt: ts },
        { id: "acc-2", name: "Bob", createdAt: ts, updatedAt: ts },
        { id: "acc-disabled", name: "Disabled", enabled: false, createdAt: ts, updatedAt: ts },
      ])
      .run();
  });

  afterEach(() => conn.close());

  function insertCred(opts: {
    id: string;
    accountId: string;
    publicKeyOpenSsh?: string | null;
    state?: "active" | "pending_confirmation";
    revoked?: boolean;
  }) {
    const publicKeyOpenSsh = opts.publicKeyOpenSsh ?? null;
    conn.db
      .insert(webauthnCredentials)
      .values({
        id: opts.id,
        accountId: opts.accountId,
        credentialId: `cred-${opts.id}`,
        publicKey: Buffer.alloc(0),
        label: `label-${opts.id}`,
        state: opts.state ?? CREDENTIAL_STATE.active,
        revoked: opts.revoked ?? false,
        publicKeyOpenSsh,
        fingerprint: fingerprintFromAuthorizedKeys(publicKeyOpenSsh),
        createdAt: new Date().toISOString(),
      })
      .run();
  }

  function makeService() {
    return createDemoAuthorizedKeysService({
      db: conn.db,
      cacheTtlMs: 1000,
      now: () => now,
    });
  }

  it("returns an empty list when no active SSH credentials exist", () => {
    const svc = makeService();
    expect(svc.lookup({ type: "x", fingerprint: "SHA256:none" })).toEqual([]);
  });

  it("matches an active credential on (type, fingerprint)", () => {
    insertCred({ id: "c1", accountId: "acc-1", publicKeyOpenSsh: KEY_A });
    const svc = makeService();
    const matches = svc.lookup({
      type: "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
      fingerprint: fingerprintOf(KEY_A),
    });
    expect(matches).toHaveLength(1);
    expect(matches[0]).toMatchObject({
      accountId: "acc-1",
      accountName: "Alice",
      credentialId: "cred-c1",
      credentialLabel: "label-c1",
      publicKeyOpenSsh: KEY_A,
    });
  });

  it("excludes pending, revoked, no-ssh-key, and disabled-account credentials", () => {
    insertCred({ id: "active", accountId: "acc-1", publicKeyOpenSsh: KEY_A });
    insertCred({
      id: "pending",
      accountId: "acc-1",
      publicKeyOpenSsh: KEY_A,
      state: "pending_confirmation",
    });
    insertCred({ id: "revoked", accountId: "acc-1", publicKeyOpenSsh: KEY_A, revoked: true });
    insertCred({ id: "no-ssh", accountId: "acc-1", publicKeyOpenSsh: null });
    insertCred({ id: "disabled", accountId: "acc-disabled", publicKeyOpenSsh: KEY_A });

    const svc = makeService();
    const matches = svc.lookup({
      type: "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
      fingerprint: fingerprintOf(KEY_A),
    });
    expect(matches).toHaveLength(1);
    expect(matches[0].credentialId).toBe("cred-active");
  });

  it("returns empty on type mismatch even when fingerprint matches", () => {
    insertCred({ id: "c1", accountId: "acc-1", publicKeyOpenSsh: KEY_A });
    const svc = makeService();
    const matches = svc.lookup({
      type: "ssh-ed25519",
      fingerprint: fingerprintOf(KEY_A),
    });
    expect(matches).toEqual([]);
  });

  it("returns all matches when two accounts share a fingerprint", () => {
    insertCred({ id: "c1", accountId: "acc-1", publicKeyOpenSsh: KEY_A });
    insertCred({ id: "c2", accountId: "acc-2", publicKeyOpenSsh: KEY_A });
    const svc = makeService();
    const matches = svc.lookup({
      type: "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
      fingerprint: fingerprintOf(KEY_A),
    });
    const accountIds = matches.map((m) => m.accountId).sort();
    expect(accountIds).toEqual(["acc-1", "acc-2"]);
  });

  it("caches the index within TTL — adds after first lookup are invisible until expiry", () => {
    insertCred({ id: "c1", accountId: "acc-1", publicKeyOpenSsh: KEY_A });
    const svc = makeService();
    expect(
      svc.lookup({
        type: "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
        fingerprint: fingerprintOf(KEY_A),
      }),
    ).toHaveLength(1);

    insertCred({ id: "c2", accountId: "acc-2", publicKeyOpenSsh: KEY_B });
    // Within TTL — second key not visible yet.
    expect(
      svc.lookup({
        type: "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
        fingerprint: fingerprintOf(KEY_B),
      }),
    ).toEqual([]);

    // After expiry — index rebuilds.
    now += 2000;
    expect(
      svc.lookup({
        type: "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
        fingerprint: fingerprintOf(KEY_B),
      }),
    ).toHaveLength(1);
  });

  it("invalidate() forces an immediate rebuild on the next lookup", () => {
    insertCred({ id: "c1", accountId: "acc-1", publicKeyOpenSsh: KEY_A });
    const svc = makeService();
    svc.lookup({
      type: "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
      fingerprint: fingerprintOf(KEY_A),
    });
    insertCred({ id: "c2", accountId: "acc-2", publicKeyOpenSsh: KEY_B });
    svc.invalidate();
    expect(
      svc.lookup({
        type: "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
        fingerprint: fingerprintOf(KEY_B),
      }),
    ).toHaveLength(1);
  });
});
