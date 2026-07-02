// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Golden characterization of the authenticated "core REST" surface that the
 * SPA and admin views depend on but that the original golden set never pinned
 * (#225): the current-account read/update, admin account management, SSH-key
 * listing, the seed export, endpoint mutations, and the two unauth meta
 * endpoints (/api/version, /config.js). Parity oracle for the Go rewrite.
 *
 * Unlike golden-http (which runs the bearer-only harness with a StubAccount-
 * Repository — findById → null, isAdmin → false), this suite owns an in-memory
 * SQLite DB and injects a real DrizzleAccountRepository seeded with the token's
 * account as the singleton admin, so /api/auth/me returns a body (not 401) and
 * the admin-gated routes return 200 (not 403). The DB is also read directly by
 * /api/accounts/export-seed and account deletion.
 *
 * Determinism: the seeded SSH key + passkey use fixed public material (so the
 * OpenSSH line / hex are stable — the default harness key is derived from a
 * per-run SSH server key), and all timestamps/fingerprints/UUIDs fold via the
 * standard normalizer. externalUrl is pinned so /config.js is port-independent.
 */
import { afterAll, afterEach, beforeAll, describe, it, onTestFailed } from "vitest";
import { createDatabase, type DatabaseConnection } from "../../db/connection.js";
import { runMigrations } from "../../db/migrate.js";
import { accounts, endpoints, webauthnCredentials } from "../../db/schema.js";
import { DrizzleAccountRepository, InMemorySshKeyRepository } from "../../db/index.js";
import {
  createTestLog,
  expectGolden,
  startTestApp,
  startTestSshServer,
  type TestAppServer,
  type TestLog,
  type TestSshServer,
} from "../helpers/index.js";

const EXTERNAL_URL = "https://shellwatch.example";
// Matches the token subject minted by startTestApp.
const ACCOUNT = "test-account-00000000-0000-0000-0000-000000000000";
// A second, non-admin account — appears in the admin list and is the (safe)
// delete target. A real UUID so it folds to "<UUID>".
const SECOND = "22222222-2222-2222-2222-222222222222";
const SEED_TS = "2026-01-01T00:00:00.000Z";

describe("Golden: account / admin / meta contract", () => {
  let log: TestLog;
  let sshServer: TestSshServer;
  let app: TestAppServer;
  let conn: DatabaseConnection;
  let baseUrls: string[];
  let ports: number[];

  beforeAll(async () => {
    log = createTestLog();
    conn = createDatabase(":memory:");
    runMigrations(conn.db);

    conn.db
      .insert(accounts)
      .values([
        {
          id: ACCOUNT,
          name: "Admin",
          enabled: true,
          maxSessions: 5,
          showDemoEndpoints: true,
          createdAt: SEED_TS,
          updatedAt: SEED_TS,
        },
        {
          id: SECOND,
          name: "Bob",
          enabled: true,
          maxSessions: 3,
          showDemoEndpoints: true,
          createdAt: "2026-01-02T00:00:00.000Z",
          updatedAt: "2026-01-02T00:00:00.000Z",
        },
      ])
      .run();

    const accountRepo = new DrizzleAccountRepository(conn.db);
    accountRepo.setAdmin(ACCOUNT);

    // Seeded directly in the DB — export-seed reads the endpoints + passkey
    // tables, not the in-memory repos.
    conn.db
      .insert(endpoints)
      .values({
        id: "ep-seed-1",
        accountId: ACCOUNT,
        label: "Prod DB",
        host: "db.internal",
        port: 2222,
        username: "deploy",
        enabled: true,
        userVerification: "required",
        agentForward: true,
        description: null,
        createdAt: SEED_TS,
        updatedAt: SEED_TS,
      })
      .run();

    conn.db
      .insert(webauthnCredentials)
      .values({
        id: "cred-row-1",
        accountId: ACCOUNT,
        credentialId: "Y29yZS1jcmVkLWE",
        publicKey: Buffer.from("a5010203262001", "hex"),
        counter: 0,
        transports: JSON.stringify(["internal", "hybrid"]),
        label: "Primary Passkey",
        publicKeyOpenSsh:
          "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBEZJWEVE shellwatch",
        revoked: false,
        state: "active",
        createdAt: SEED_TS,
      })
      .run();

    // Deterministic file key (the default harness key is per-run).
    const keyRepo = new InMemorySshKeyRepository([
      {
        id: "key-1",
        label: "Deploy Key",
        type: "file",
        publicKey:
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZJWEVEREVURVJNSU5JU1RJQ0tFWU1BVEVSSUFM deploy@shellwatch",
        fingerprint: "SHA256:Rml4ZWREZXRlcm1pbmlzdGljRmluZ2VycHJpbnRWYWx1ZQ",
        createdAt: SEED_TS,
      },
    ]);

    sshServer = await startTestSshServer(log);
    app = await startTestApp(sshServer, log, { accountRepo, keyRepo, db: conn.db });
    baseUrls = [app.url, EXTERNAL_URL];
    ports = [app.port, sshServer.port];
    app.config.server.externalUrl = EXTERNAL_URL;
  });

  afterAll(async () => {
    await app?.close();
    await sshServer?.close();
    conn?.close();
  });

  afterEach(() => {
    onTestFailed(() => log.dump());
    log.clear();
  });

  /** Capture {status, body} of an authenticated request. */
  async function snap(name: string, path: string, init?: RequestInit) {
    const res = await app.fetch(path, init);
    const body = await res.json().catch(() => null);
    expectGolden(
      import.meta.url,
      name,
      { request: { path }, status: res.status, body },
      { baseUrls, ports },
    );
  }

  /** Capture {status, contentType, body} of a text (non-JSON) response. */
  async function snapText(name: string, path: string) {
    const res = await app.fetch(path);
    const body = await res.text();
    expectGolden(
      import.meta.url,
      name,
      {
        request: { path },
        status: res.status,
        contentType: res.headers.get("content-type"),
        body,
      },
      { baseUrls, ports },
    );
  }

  const json = (method: string, body: unknown): RequestInit => ({
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });

  describe("meta (unauthenticated)", () => {
    it("GET /api/version", () => snap("meta-version", "/api/version"));
    it("GET /config.js", () => snapText("meta-config-js", "/config.js"));
  });

  describe("current account", () => {
    // Reads must precede the update below (same app instance, shared state).
    it("GET /api/auth/me", () => snap("account-me", "/api/auth/me"));
  });

  describe("admin: accounts + keys + export", () => {
    it("GET /api/accounts", () => snap("account-list", "/api/accounts"));
    it("GET /api/keys", () => snap("keys-list", "/api/keys"));
    it("GET /api/accounts/export-seed", () =>
      snap("account-export-seed", "/api/accounts/export-seed"));
  });

  describe("mutations (run last — they change shared state)", () => {
    it("PUT /api/auth/me", () =>
      snap("account-update", "/api/auth/me", json("PUT", { name: "Renamed Admin" })));
    it("PUT /api/endpoints/:id", () =>
      snap("endpoint-update", "/api/endpoints/test-server", json("PUT", { label: "Renamed Box" })));
    it("DELETE /api/endpoints/:id", () =>
      snap("endpoint-delete", "/api/endpoints/test-server", { method: "DELETE" }));
    it("DELETE /api/accounts/:id (non-admin target)", () =>
      snap("account-delete", `/api/accounts/${SECOND}`, { method: "DELETE" }));
  });
});
