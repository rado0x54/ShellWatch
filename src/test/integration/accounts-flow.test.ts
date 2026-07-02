// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Integration coverage for the account-management routes (#225 item 3):
 * GET /api/auth/me, and the admin-only GET /api/accounts,
 * DELETE /api/accounts/:id, GET /api/accounts/export-seed.
 *
 * startTestApp's StubAccountRepository can't model admin (isAdmin === false,
 * findById === null), so this uses a thin app backed by a real in-memory DB +
 * DrizzleAccountRepository with a seeded admin + normal account.
 */
import fastifyRateLimit from "@fastify/rate-limit";
import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createDatabase, type DatabaseConnection } from "../../db/connection.js";
import { runMigrations } from "../../db/migrate.js";
import { DrizzleAccountRepository } from "../../db/repositories/account-repo.js";
import { accounts } from "../../db/schema.js";
import { createDemoEndpointsService } from "../../demo-endpoints/index.js";
import { createBearerResolver } from "../../hydra/bearer-resolver.js";
import { AccountLifecycle } from "../../server/account-lifecycle.js";
import { registerBearerGate } from "../../server/auth/bearer-gate.js";
import { registerAccountRoutes } from "../../server/routes/accounts.js";
import { makeTestBearer } from "../helpers/test-bearer.js";
import { makeTestConfig } from "../helpers/test-config.js";

const ADMIN = "00000000-0000-0000-0000-0000000admin";
const NORMAL = "00000000-0000-0000-0000-000000normal";

interface AccountsApp {
  app: FastifyInstance;
  conn: DatabaseConnection;
  authAdmin: string;
  authNormal: string;
}

async function makeApp(): Promise<AccountsApp> {
  const conn = createDatabase(":memory:");
  runMigrations(conn.db);

  const now = new Date().toISOString();
  conn.db
    .insert(accounts)
    .values([
      { id: ADMIN, name: "Admin", createdAt: now, updatedAt: now },
      { id: NORMAL, name: "Normal", createdAt: now, updatedAt: now },
    ])
    .run();

  const accountRepo = new DrizzleAccountRepository(conn.db);
  accountRepo.setAdmin(ADMIN);

  const app = Fastify({ logger: false });
  app.decorateRequest("accountId", "");
  app.decorateRequest("apiKey", null);
  await app.register(fastifyRateLimit, { global: false });

  const config = makeTestConfig();
  const { admin, bearerFor } = makeTestBearer();
  registerBearerGate({
    app,
    resolveBearer: createBearerResolver({ admin, cacheTtlMs: 0 }),
    accountRepo,
    config,
    agentProxyEnabled: false,
  });
  registerAccountRoutes({
    app,
    accountRepo,
    demoEndpoints: createDemoEndpointsService([]),
    db: conn.db,
    accountLifecycle: new AccountLifecycle(),
  });
  await app.ready();

  return { app, conn, authAdmin: bearerFor(ADMIN), authNormal: bearerFor(NORMAL) };
}

describe("Account management flow", () => {
  let c: AccountsApp;

  beforeEach(async () => {
    c = await makeApp();
  });

  afterEach(() => {
    c.conn.close();
  });

  const get = (url: string, auth: string) =>
    c.app.inject({ method: "GET", url, headers: { authorization: auth } });

  it("GET /api/auth/me returns the caller's profile with isAdmin", async () => {
    const res = await get("/api/auth/me", c.authAdmin);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ id: ADMIN, name: "Admin", isAdmin: true });
  });

  it("GET /api/accounts lists all accounts for an admin", async () => {
    const res = await get("/api/accounts", c.authAdmin);
    expect(res.statusCode).toBe(200);
    const ids = res.json().accounts.map((a: { id: string }) => a.id);
    expect(ids).toEqual(expect.arrayContaining([ADMIN, NORMAL]));
    const adminRow = res.json().accounts.find((a: { id: string }) => a.id === ADMIN);
    expect(adminRow.isAdmin).toBe(true);
  });

  it("GET /api/accounts is admin-only (403 for a normal account)", async () => {
    const res = await get("/api/accounts", c.authNormal);
    expect(res.statusCode).toBe(403);
  });

  it("GET /api/accounts/export-seed returns seed config for an admin", async () => {
    const res = await get("/api/accounts/export-seed", c.authAdmin);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ passkeys: [], endpoints: [] });
  });

  it("GET /api/accounts/export-seed is admin-only (403)", async () => {
    const res = await get("/api/accounts/export-seed", c.authNormal);
    expect(res.statusCode).toBe(403);
  });

  it("DELETE /api/accounts/:id removes a non-admin account", async () => {
    const res = await c.app.inject({
      method: "DELETE",
      url: `/api/accounts/${NORMAL}`,
      headers: { authorization: c.authAdmin },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: "deleted" });

    const list = await get("/api/accounts", c.authAdmin);
    expect(list.json().accounts.map((a: { id: string }) => a.id)).not.toContain(NORMAL);
  });

  it("DELETE refuses to delete your own account (400)", async () => {
    const res = await c.app.inject({
      method: "DELETE",
      url: `/api/accounts/${ADMIN}`,
      headers: { authorization: c.authAdmin },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toMatch(/your own account/i);
  });
});
