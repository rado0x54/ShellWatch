// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Golden characterization of the Hydra-fronted REST surface (#225): authorized-
 * client listing + revocation (#219), mediated DCR (#217), and the consent
 * provider's JSON endpoints. Parity oracle for the Go rewrite.
 *
 * Uses the in-memory-DB harness (like golden-account) because the consent
 * provider routes mount only when `db` is present (app.ts / hydra/routes.ts).
 * The fake Hydra admin is seeded deterministically: consent-session rows for
 * the listing, a consent request for the approve flow, and a real in-memory
 * client store for DCR.
 *
 * Two consent ops are excluded here (documented in golden-coverage.ts):
 *  - `startHydraConsent` (consent/options) is a @simplewebauthn assertion-options
 *    passthrough — the same category the other /options ops are excluded under.
 *  - `finishHydraConsent` (consent/verify) — its `{ redirectTo }` envelope is
 *    already pinned by webauthn-login-verify, and the success path needs a full
 *    DB-enrolled WebAuthn ceremony (deferred).
 * `client_id_issued_at` (DCR, epoch-seconds) folds via TS_KEYS in golden.ts.
 */
import { afterAll, afterEach, beforeAll, describe, it, onTestFailed } from "vitest";
import { createDatabase, type DatabaseConnection } from "../../db/connection.js";
import { runMigrations } from "../../db/migrate.js";
import { accounts, webauthnCredentials } from "../../db/schema.js";
import { DrizzleAccountRepository } from "../../db/index.js";
import { mintStepUpToken, STEPUP_ACTION } from "../../webauthn/stepup-store.js";
import type { HydraConsentRequest, HydraConsentSession } from "../../hydra/types.js";
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

describe("Golden: Hydra / consent / DCR contract", () => {
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

    // One active passkey so consent/options can enumerate a credential id.
    conn.db
      .insert(webauthnCredentials)
      .values({
        id: "cred-consent-1",
        accountId: ACCOUNT,
        credentialId: "Y29uc2VudC1jcmVkLWlk",
        publicKey: Buffer.from("a5010203262001", "hex"),
        counter: 0,
        transports: JSON.stringify(["internal"]),
        label: "Primary Passkey",
        publicKeyOpenSsh:
          "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBEZJWEVE shellwatch",
        revoked: false,
        state: "active",
        createdAt: SEED_TS,
      })
      .run();

    const accountRepo = new DrizzleAccountRepository(conn.db);
    accountRepo.setAdmin(ACCOUNT);

    sshServer = await startTestSshServer(log);
    app = await startTestApp(sshServer, log, { accountRepo, db: conn.db });
    baseUrls = [app.url];
    ports = [app.port, sshServer.port];

    const spaId = app.config.hydra.spa.clientId;
    // Authorized-client list: the first-party SPA (→ current:true) + one MCP grant.
    app.hydraAdmin.setConsentSessions(ACCOUNT, [
      {
        consent_request: { client: { client_id: spaId, client_name: "ShellWatch Web" } },
        grant_scope: ["ui", "offline_access"],
        handled_at: "2026-01-01T00:00:00Z",
      },
      {
        consent_request: {
          client: { client_id: "mcp-abc", client_name: "Claude MCP", created_at: "2026-01-30Z" },
        },
        grant_scope: ["mcp", "offline_access"],
        handled_at: "2026-02-01T00:00:00Z",
      },
    ] as HydraConsentSession[]);

    // Consent request for the no-passkey approve flow (option-1: fresh login).
    app.hydraAdmin.setConsentRequest("consent-approve-chal", {
      challenge: "consent-approve-chal",
      skip: false,
      subject: ACCOUNT,
      client: { client_id: "mcp-abc", client_name: "Claude MCP" },
      requested_scope: ["mcp", "offline_access"],
      requested_access_token_audience: [],
      context: { freshLogin: true },
    } as HydraConsentRequest);
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

  const json = (body: unknown, headers: Record<string, string> = {}): RequestInit => ({
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });

  /** Authenticated (ui-token) capture. */
  async function snapAuthed(name: string, path: string, init?: RequestInit) {
    const res = await app.fetch(path, init);
    const body = await res.json().catch(() => null);
    expectGolden(
      import.meta.url,
      name,
      { request: { path }, status: res.status, body },
      { baseUrls, ports },
    );
  }

  /** Public (unauthenticated provider/DCR) capture. */
  async function snapPublic(name: string, path: string, init?: RequestInit) {
    const res = await fetch(`${app.url}${path}`, init);
    const body = await res.json().catch(() => null);
    expectGolden(
      import.meta.url,
      name,
      { request: { path }, status: res.status, body },
      { baseUrls, ports },
    );
  }

  describe("authorized clients (#219)", () => {
    it("GET /api/auth/sessions", () => snapAuthed("auth-sessions-list", "/api/auth/sessions"));

    it("DELETE /api/auth/sessions/:clientId (step-up)", () =>
      snapAuthed("auth-session-revoke", "/api/auth/sessions/mcp-abc", {
        method: "DELETE",
        headers: {
          [STEPUP_HEADER]: mintStepUpToken({
            accountId: ACCOUNT,
            action: STEPUP_ACTION.revokeSession,
          }).token,
        },
      }));

    it("POST /api/auth/sessions/revoke-all (step-up)", () =>
      snapAuthed(
        "auth-session-revoke-all",
        "/api/auth/sessions/revoke-all",
        json(
          {},
          {
            [STEPUP_HEADER]: mintStepUpToken({
              accountId: ACCOUNT,
              action: STEPUP_ACTION.revokeAllSessions,
            }).token,
          },
        ),
      ));
  });

  describe("mediated DCR (#217)", () => {
    // client_id_issued_at (DCR epoch-seconds) folds via TS_KEYS in golden.ts.
    it("POST /api/hydra/register", () =>
      snapPublic(
        "dcr-register",
        "/api/hydra/register",
        json({
          client_name: "Test MCP",
          redirect_uris: ["http://127.0.0.1:9876/callback"],
          scope: "mcp",
        }),
      ));
  });

  describe("consent provider (JSON)", () => {
    // startHydraConsent (consent/options) is excluded — @simplewebauthn
    // assertion-options passthrough (see golden-coverage.ts).
    it("POST /api/hydra/consent/approve (approveHydraConsent, no-passkey option-1)", () =>
      snapPublic(
        "consent-approve",
        "/api/hydra/consent/approve",
        json({ consent_challenge: "consent-approve-chal" }),
      ));
  });
});
