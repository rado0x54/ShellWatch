// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Integration coverage for the Web Push subscription routes
 * (`POST`/`DELETE /api/push/subscribe`) — the last REST surface without
 * integration coverage (#225 item 3). Routes are only mounted when a
 * pushSubRepo is supplied, so the test wires a real in-memory one.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, onTestFailed } from "vitest";
import { createDatabase, type DatabaseConnection } from "../../db/connection.js";
import { runMigrations } from "../../db/migrate.js";
import { DrizzlePushSubscriptionRepository } from "../../db/repositories/push-subscription-repo.js";
import { accounts } from "../../db/schema.js";
import {
  createTestLog,
  startTestApp,
  startTestSshServer,
  type TestAppServer,
  type TestLog,
  type TestSshServer,
} from "../helpers/index.js";

// fcm.googleapis.com is on the allow-list (push-endpoint-validator.ts).
const FCM = "https://fcm.googleapis.com/fcm/send/abc123";
const KEYS = { p256dh: "BPk-test-p256dh", auth: "test-auth" };

describe("Web Push subscription flow", () => {
  let log: TestLog;
  let sshServer: TestSshServer;
  let app: TestAppServer;
  let conn: DatabaseConnection;
  let repo: DrizzlePushSubscriptionRepository;

  beforeAll(async () => {
    log = createTestLog();
    conn = createDatabase(":memory:");
    runMigrations(conn.db);
    repo = new DrizzlePushSubscriptionRepository(conn.db);
    sshServer = await startTestSshServer(log);
    app = await startTestApp(sshServer, log, { pushSubRepo: repo });

    // push_subscriptions.accountId FKs accounts.id — seed the caller's account
    // (the token subject) plus a second account for the cross-account 409 case.
    const now = new Date().toISOString();
    conn.db
      .insert(accounts)
      .values([
        { id: app.accountId, name: "Test", createdAt: now, updatedAt: now },
        { id: "another-account", name: "Other", createdAt: now, updatedAt: now },
      ])
      .run();
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

  const post = (body: unknown) =>
    app.fetch("/api/push/subscribe", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });

  it("registers a subscription for an allow-listed endpoint", async () => {
    const res = await post({ endpoint: FCM, keys: KEYS });
    expect(res.status).toBe(200);
    expect((await res.json()).id).toBeTruthy();
  });

  it("rejects an endpoint that is not a recognized push service (400)", async () => {
    const res = await post({ endpoint: "https://evil.example.com/x", keys: KEYS });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/recognized push service/i);
  });

  it("rejects a subscription missing keys (400)", async () => {
    const res = await post({ endpoint: FCM });
    expect(res.status).toBe(400);
  });

  it("409 when the endpoint is already registered to a different account", async () => {
    const endpoint = "https://fcm.googleapis.com/fcm/send/owned-by-other";
    repo.upsert({ accountId: "another-account", endpoint, p256dh: "x", auth: "y" });
    const res = await post({ endpoint, keys: KEYS });
    expect(res.status).toBe(409);
    expect((await res.json()).error).toMatch(/different account/i);
  });

  it("unsubscribes (ok:true), and 400 without an endpoint", async () => {
    await post({ endpoint: FCM, keys: KEYS }); // ensure it exists
    const del = await app.fetch("/api/push/subscribe", {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ endpoint: FCM }),
    });
    expect(del.status).toBe(200);
    expect(await del.json()).toEqual({ ok: true });

    const bad = await app.fetch("/api/push/subscribe", {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(bad.status).toBe(400);
  });
});
