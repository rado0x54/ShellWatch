// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Golden characterization of the pending-action (human-in-the-loop signing
 * approval) + Web Push REST surfaces (#225). Parity oracle for the Go rewrite.
 *
 * Both surfaces are opt-in: buildApp mounts /api/actions/* only when an
 * actionStore + wsChannel are supplied, and /api/push/subscribe only with a
 * pushSubRepo. This suite constructs a real PendingActionStore (seeded with
 * `key-approve` actions — the payload-free variant, so no WebAuthn assertion is
 * needed to resolve) and a Drizzle push repo over an in-memory DB.
 *
 * Determinism: action ids are random base64url (not a normalizer-folded
 * pattern), so the `id` in the body is folded to "<ID>" and the URL segment to
 * "{actionId}" by hand. createdAt/expiresAt (epoch-ms numbers) fold to <TS> via
 * the key-name rule; keyFingerprint → <FINGERPRINT>; the push row id (UUID) →
 * <UUID>. The push endpoint is a fixed fcm.googleapis.com URL so it passes the
 * SSRF allowlist deterministically.
 */
import { afterAll, afterEach, beforeAll, describe, it, onTestFailed } from "vitest";
import { createDatabase, type DatabaseConnection } from "../../db/connection.js";
import { runMigrations } from "../../db/migrate.js";
import { accounts } from "../../db/schema.js";
import { PendingActionStore, WebSocketChannel } from "../../pending-action/index.js";
import { DrizzlePushSubscriptionRepository } from "../../db/repositories/push-subscription-repo.js";
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
const PUSH_ENDPOINT = "https://fcm.googleapis.com/fcm/send/cG9ydGFibGUtZml4ZWQtdG9rZW4";

function keyApprove(store: PendingActionStore) {
  return store.create({
    type: "key-approve",
    accountId: ACCOUNT,
    context: {
      source: "endpoint-auth",
      endpointLabel: "Prod DB",
      endpointAddress: "deploy@db.internal:2222",
      trigger: { kind: "mcp", reason: "deploy hotfix", mcpClientName: "codex" },
    },
    keyLabel: "Deploy Key",
    keyFingerprint: "SHA256:Rml4ZWREZXRlcm1pbmlzdGljRmluZ2VycHJpbnRWYWx1ZQ",
    redirectTo: "/sign/approved",
    resolve: () => {},
    reject: () => {},
  });
}

describe("Golden: pending-action + push contract", () => {
  let log: TestLog;
  let sshServer: TestSshServer;
  let app: TestAppServer;
  let conn: DatabaseConnection;
  let store: PendingActionStore;
  let getId: string;
  let resolveId: string;
  let denyId: string;

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

    store = new PendingActionStore();
    const wsChannel = new WebSocketChannel();
    const pushSubRepo = new DrizzlePushSubscriptionRepository(conn.db);

    // Distinct actions so the read target isn't consumed by resolve/deny.
    getId = keyApprove(store).id;
    resolveId = keyApprove(store).id;
    denyId = keyApprove(store).id;

    sshServer = await startTestSshServer(log);
    app = await startTestApp(sshServer, log, { actionStore: store, wsChannel, pushSubRepo });
  });

  afterAll(async () => {
    await app?.close();
    await sshServer?.close();
    store?.destroy();
    conn?.close();
  });

  afterEach(() => {
    onTestFailed(() => log.dump());
    log.clear();
  });

  /** Capture, folding a leading /api/actions/<id> segment to {actionId} and a body `id` to <ID>. */
  async function snapAction(name: string, actionId: string, suffix: string, init?: RequestInit) {
    const res = await app.fetch(`/api/actions/${actionId}${suffix}`, init);
    const body = (await res.json().catch(() => null)) as Record<string, unknown> | null;
    if (body && typeof body.id === "string") body.id = "<ID>";
    expectGolden(import.meta.url, name, {
      request: { path: `/api/actions/{actionId}${suffix}` },
      status: res.status,
      body,
    });
  }

  const json = (method: string, body: unknown): RequestInit => ({
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });

  describe("pending actions", () => {
    it("GET /api/actions/:actionId", () => snapAction("action-get", getId, ""));
    it("POST /api/actions/:actionId/resolve (key-approve)", () =>
      snapAction("action-resolve", resolveId, "/resolve", { method: "POST" }));
    it("POST /api/actions/:actionId/deny", () =>
      snapAction("action-deny", denyId, "/deny", { method: "POST" }));
  });

  describe("web push", () => {
    it("POST /api/push/subscribe", async () => {
      const res = await app.fetch(
        "/api/push/subscribe",
        json("POST", {
          endpoint: PUSH_ENDPOINT,
          keys: { p256dh: "BFixedP256dhPublicKeyValueForGoldenDeterminism", auth: "Rml4ZWRBdXRo" },
        }),
      );
      const body = await res.json().catch(() => null);
      expectGolden(import.meta.url, "push-subscribe", {
        request: { path: "/api/push/subscribe" },
        status: res.status,
        body,
      });
    });

    it("DELETE /api/push/subscribe", async () => {
      const res = await app.fetch(
        "/api/push/subscribe",
        json("DELETE", { endpoint: PUSH_ENDPOINT }),
      );
      const body = await res.json().catch(() => null);
      expectGolden(import.meta.url, "push-unsubscribe", {
        request: { path: "/api/push/subscribe" },
        status: res.status,
        body,
      });
    });
  });
});
