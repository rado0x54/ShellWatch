// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Golden characterization of the audit query surface — the paged row envelopes
 * ({ rows, nextCursor }), keyset pagination across pages, single-row lookup, and
 * the invalid-filter 400. Parity oracle for the Go rewrite (#225 item 2); this
 * is the most structurally complex response in the API.
 *
 * Unlike the other golden suites, this one owns an in-memory SQLite DB with
 * deterministic seed rows and wires the audit repos into the app (they are not
 * mounted by default). `nextCursor` is opaque and data-derived, so it is folded
 * to "<CURSOR>" in goldens; page 2 is fetched with the *real* cursor read back
 * from page 1.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, onTestFailed } from "vitest";
import { createDatabase, type DatabaseConnection } from "../../db/connection.js";
import { runMigrations } from "../../db/migrate.js";
import { accounts, auditSessionLifecycle, auditSigningRequests } from "../../db/schema.js";
import { DrizzleSessionLifecycleRepository } from "../../audit/session-lifecycle-repo.js";
import { DrizzleSigningRequestsRepository } from "../../audit/signing-requests-repo.js";
import {
  createTestLog,
  expectGolden,
  startTestApp,
  startTestSshServer,
  type TestAppServer,
  type TestLog,
  type TestSshServer,
} from "../helpers/index.js";

// Matches the token subject minted by startTestApp.
const ACCOUNT = "test-account-00000000-0000-0000-0000-000000000000";

describe("Golden: audit contract", () => {
  let log: TestLog;
  let sshServer: TestSshServer;
  let app: TestAppServer;
  let conn: DatabaseConnection;

  beforeAll(async () => {
    log = createTestLog();
    conn = createDatabase(":memory:");
    runMigrations(conn.db);

    conn.db
      .insert(accounts)
      .values({ id: ACCOUNT, name: "Audit", createdAt: "<seed>", updatedAt: "<seed>" })
      .run();

    // Three lifecycle rows, ascending created_at (list returns DESC).
    conn.db
      .insert(auditSessionLifecycle)
      .values([
        {
          sessionId: "sess_000000000001",
          accountId: ACCOUNT,
          endpointId: "audit-endpoint-1",
          source: "ui",
          status: "open",
          createdAt: "2026-01-01T00:00:01.000Z",
          sourceIp: "203.0.113.1",
        },
        {
          sessionId: "sess_000000000002",
          accountId: ACCOUNT,
          endpointId: "audit-endpoint-2",
          source: "mcp",
          status: "closed",
          createdAt: "2026-01-01T00:00:02.000Z",
          closedAt: "2026-01-01T00:00:05.000Z",
          durationMs: 3000,
          mcpReason: "deploy hotfix",
          mcpClientName: "codex",
          closeReason: "client.mcp",
        },
        {
          sessionId: "sess_000000000003",
          accountId: ACCOUNT,
          endpointId: "audit-endpoint-3",
          source: "ssh",
          status: "error",
          createdAt: "2026-01-01T00:00:03.000Z",
          closeReason: "transport-error",
        },
      ])
      .run();

    // Three signing rows, ascending created_at.
    conn.db
      .insert(auditSigningRequests)
      .values([
        {
          id: "act_0000000000000000000001",
          accountId: ACCOUNT,
          type: "webauthn-sign",
          source: "endpoint-auth",
          createdAt: "2026-01-01T00:00:01.000Z",
          resolvedAt: "2026-01-01T00:00:02.000Z",
          outcome: "approved",
          latencyMs: 1200,
          endpointLabel: "Prod Web",
          endpointAddress: "ubuntu@web-01:22",
          credentialId: "cred-abc",
          passkeyLabel: "YubiKey 5",
          userVerification: "required",
        },
        {
          id: "act_0000000000000000000002",
          accountId: ACCOUNT,
          type: "key-approve",
          source: "agent-forwarding",
          createdAt: "2026-01-01T00:00:02.000Z",
          resolvedAt: "2026-01-01T00:00:03.000Z",
          outcome: "denied",
          latencyMs: 800,
          sessionId: "sess_000000000002",
          keyLabel: "deploy key",
          keyFingerprint: "SHA256:AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKK",
        },
        {
          id: "act_0000000000000000000003",
          accountId: ACCOUNT,
          type: "webauthn-sign",
          source: "agent-proxy",
          createdAt: "2026-01-01T00:00:03.000Z",
          outcome: null,
          clientHostname: "laptop.local",
          clientOs: "darwin/arm64",
          clientVersion: "1.2.3",
        },
      ])
      .run();

    sshServer = await startTestSshServer(log);
    app = await startTestApp(sshServer, log, {
      sessionLifecycleRepo: new DrizzleSessionLifecycleRepository(conn.db),
      signingRequestsRepo: new DrizzleSigningRequestsRepository(conn.db),
    });
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

  async function get(path: string) {
    const res = await app.fetch(path);
    return { status: res.status, body: await res.json().catch(() => null) };
  }

  it("session lifecycle — paginates with keyset cursor", async () => {
    const res = await app.fetch("/api/audit/sessions?limit=2");
    const page1 = await res.json();
    expectGolden(import.meta.url, "audit-sessions-page1", { status: res.status, body: page1 });
    expect(page1.nextCursor).toBeTruthy();
    expect(page1.rows).toHaveLength(2);

    const p2 = await get(
      `/api/audit/sessions?limit=2&cursor=${encodeURIComponent(page1.nextCursor)}`,
    );
    expectGolden(import.meta.url, "audit-sessions-page2", p2);
    expect(p2.body.rows).toHaveLength(1);
    expect(p2.body.nextCursor).toBeNull();
  });

  it("signing requests — first page + single-row lookup + invalid filter", async () => {
    expectGolden(import.meta.url, "audit-signings-page1", await get("/api/audit/signings?limit=2"));
    expectGolden(
      import.meta.url,
      "audit-signings-by-id",
      await get("/api/audit/signings/act_0000000000000000000001"),
    );
    expectGolden(
      import.meta.url,
      "audit-signings-invalid-source",
      await get("/api/audit/signings?source=bogus"),
    );
  });
});
