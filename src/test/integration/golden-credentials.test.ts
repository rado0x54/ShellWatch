// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Golden characterization of the passkey-credential management surface + the
 * invite-read endpoints the SPA settings pages depend on (#225): list, confirm
 * (pending → active), rename, revoke, the anonymous passkey-status probe, and
 * the two invite reads. Parity oracle for the Go rewrite.
 *
 * Uses the same in-memory-DB harness as golden-account (the credential + invite
 * routes mount only when buildApp gets a `db`). Determinism: fixed credential
 * material (credentialId / COSE public key / OpenSSH line), so algorithm +
 * fingerprint are stable; the normalizer folds timestamps → <TS>, fingerprints
 * → <FINGERPRINT>, and any `token` → <REDACTED>. Step-up-gated mutations
 * (confirm, revoke) get a token minted directly via `mintStepUpToken` and
 * presented in the x-shellwatch-stepup-token header — no ceremony needed.
 *
 * getPasskeyInviteByToken's path carries a per-run random token; the captured
 * `request.path` folds that segment to <REDACTED> so the fixture is stable (the
 * body is what this pins).
 */
import { afterAll, afterEach, beforeAll, describe, it, onTestFailed } from "vitest";
import { createDatabase, type DatabaseConnection } from "../../db/connection.js";
import { runMigrations } from "../../db/migrate.js";
import { accounts, webauthnCredentials } from "../../db/schema.js";
import { CREDENTIAL_STATE } from "../../db/repositories/credential-queries.js";
import { _resetInviteStore } from "../../webauthn/invite-store.js";
import { _resetStepUpStore, mintStepUpToken, STEPUP_ACTION } from "../../webauthn/stepup-store.js";
import {
  createTestLog,
  expectGolden,
  startTestApp,
  startTestSshServer,
  type TestAppServer,
  type TestLog,
  type TestSshServer,
} from "../helpers/index.js";

const ACCOUNT = "test-account-00000000-0000-0000-0000-000000000000";
const SEED_TS = "2026-01-01T00:00:00.000Z";
const STEPUP_HEADER = "x-shellwatch-stepup-token";
const EXTERNAL_URL = "https://shellwatch.example";

// Two active credentials (so the "last active passkey" guard permits revoking
// one) plus a pending one (the confirm target).
const CRED_ACTIVE_1 = "cred-active-1";
const CRED_ACTIVE_2 = "cred-active-2";
const CRED_PENDING = "cred-pending-1";
const COSE = Buffer.from("a5010203262001215820aa225820bb", "hex");

describe("Golden: passkey credentials + invite reads", () => {
  let log: TestLog;
  let sshServer: TestSshServer;
  let app: TestAppServer;
  let conn: DatabaseConnection;
  let baseUrls: string[];
  let ports: number[];

  beforeAll(async () => {
    _resetInviteStore();
    _resetStepUpStore();
    log = createTestLog();
    conn = createDatabase(":memory:");
    runMigrations(conn.db);

    conn.db
      .insert(accounts)
      .values({
        id: ACCOUNT,
        name: "Admin",
        enabled: true,
        maxSessions: 5,
        showDemoEndpoints: true,
        createdAt: SEED_TS,
        updatedAt: SEED_TS,
      })
      .run();

    conn.db
      .insert(webauthnCredentials)
      .values([
        {
          id: CRED_ACTIVE_1,
          accountId: ACCOUNT,
          credentialId: "Y3JlZC1hY3RpdmUtMQ",
          publicKey: COSE,
          counter: 0,
          transports: JSON.stringify(["internal"]),
          label: "Primary",
          publicKeyOpenSsh:
            "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhAAAACG5pc3RwMjU2AAAAQQRQUklNQVJZ primary",
          revoked: false,
          state: CREDENTIAL_STATE.active,
          createdAt: SEED_TS,
        },
        {
          id: CRED_ACTIVE_2,
          accountId: ACCOUNT,
          credentialId: "Y3JlZC1hY3RpdmUtMg",
          publicKey: COSE,
          counter: 0,
          transports: JSON.stringify(["hybrid"]),
          label: "Backup",
          publicKeyOpenSsh:
            "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhAAAACG5pc3RwMjU2AAAAQQRCQUNLVVA backup",
          revoked: false,
          state: CREDENTIAL_STATE.active,
          createdAt: SEED_TS,
        },
        {
          id: CRED_PENDING,
          accountId: ACCOUNT,
          credentialId: "Y3JlZC1wZW5kaW5nLTE",
          publicKey: COSE,
          counter: 0,
          transports: JSON.stringify(["internal"]),
          label: "Pending Device",
          publicKeyOpenSsh:
            "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhAAAACG5pc3RwMjU2AAAAQQRQRU5ESU5H pending",
          revoked: false,
          state: CREDENTIAL_STATE.pendingConfirmation,
          createdAt: SEED_TS,
        },
      ])
      .run();

    sshServer = await startTestSshServer(log);
    app = await startTestApp(sshServer, log, { db: conn.db });
    baseUrls = [app.url, EXTERNAL_URL];
    ports = [app.port, sshServer.port];
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

  async function snap(name: string, path: string, init?: RequestInit, pathOverride?: string) {
    const res = await app.fetch(path, init);
    const body = await res.json().catch(() => null);
    expectGolden(
      import.meta.url,
      name,
      { request: { path: pathOverride ?? path }, status: res.status, body },
      { baseUrls, ports },
    );
  }

  const json = (method: string, body: unknown): RequestInit => ({
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });

  const stepUpHeader = (action: (typeof STEPUP_ACTION)[keyof typeof STEPUP_ACTION]) => ({
    [STEPUP_HEADER]: mintStepUpToken({ accountId: ACCOUNT, action }).token,
  });

  describe("reads", () => {
    it("GET /api/auth/passkey-status", () => snap("passkey-status", "/api/auth/passkey-status"));
    it("GET /api/webauthn/credentials", () =>
      snap("credentials-list", "/api/webauthn/credentials"));

    it("GET /api/webauthn/invite (after mint)", async () => {
      await app.fetch("/api/webauthn/invite", { method: "POST" }); // seed the slot
      await snap("invite-get", "/api/webauthn/invite");
    });

    it("GET /api/passkey-invite/:token", async () => {
      const mint = await app.fetch("/api/webauthn/invite", { method: "POST" });
      const token = (await mint.json()).invite.token as string;
      await snap(
        "invite-by-token",
        `/api/passkey-invite/${token}`,
        undefined,
        "/api/passkey-invite/<REDACTED>",
      );
    });
  });

  describe("mutations (run last)", () => {
    it("PATCH /api/webauthn/credentials/:id/label", () =>
      snap(
        "credential-label",
        `/api/webauthn/credentials/${CRED_ACTIVE_1}/label`,
        json("PATCH", { label: "Renamed Primary" }),
      ));

    it("POST /api/webauthn/credentials/:id/confirm (step-up)", () =>
      snap(`credential-confirm`, `/api/webauthn/credentials/${CRED_PENDING}/confirm`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...stepUpHeader(STEPUP_ACTION.confirmPasskey),
        },
        body: "{}",
      }));

    it("POST /api/webauthn/credentials/:id/revoke (step-up)", () =>
      snap(`credential-revoke`, `/api/webauthn/credentials/${CRED_ACTIVE_2}/revoke`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...stepUpHeader(STEPUP_ACTION.revokePasskey),
        },
        body: JSON.stringify({ invalidateSessions: false }),
      }));
  });
});
