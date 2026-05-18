// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import type { AccountInfo, AccountRepository } from "../../db/index.js";
import type { DemoEndpoint } from "../../config/schema.js";
import { createDemoEndpointsService } from "../../demo-endpoints/index.js";
import { AccountLifecycle } from "../account-lifecycle.js";
import { registerAccountRoutes } from "./accounts.js";

const ADMIN_ID = "admin-id";
const TARGET_ID = "target-id";

function stubAccount(id: string, isAdmin: boolean): AccountInfo {
  const now = new Date().toISOString();
  return {
    id,
    name: id,
    isAdmin,
    enabled: true,
    maxSessions: 5,
    showDemoEndpoints: true,
    lastUsedAt: null,
    createdAt: now,
    updatedAt: now,
  };
}

// Minimal AccountRepository for route tests — only the methods this route hits.
function fakeRepo(opts: { adminId: string }): AccountRepository {
  return {
    async findById(id) {
      return stubAccount(id, id === opts.adminId);
    },
    async findAll() {
      return [];
    },
    async update() {},
    touchLastUsed() {},
    flushLastUsed() {},
    getAdminAccountId() {
      return opts.adminId;
    },
    setAdmin() {},
    isAdmin(id) {
      return id === opts.adminId;
    },
    destroy() {},
  };
}

async function buildApp(
  callerAccountId: string,
  opts: { demoEndpoints?: readonly DemoEndpoint[] } = {},
) {
  const app = Fastify({ logger: false });
  const accountRepo = fakeRepo({ adminId: ADMIN_ID });
  const accountLifecycle = new AccountLifecycle();
  app.decorateRequest("accountId", "");
  app.addHook("onRequest", async (request) => {
    request.accountId = callerAccountId;
  });
  registerAccountRoutes({
    app,
    accountRepo,
    demoEndpoints: createDemoEndpointsService(opts.demoEndpoints ?? []),
    accountLifecycle,
    db: null,
  });
  return { app, accountLifecycle };
}

describe("DELETE /api/accounts/:id lifecycle emit", () => {
  it("emits `deleted` for the target id when the admin deletes another account", async () => {
    const { app, accountLifecycle } = await buildApp(ADMIN_ID);
    const handler = vi.fn();
    accountLifecycle.on("deleted", handler);

    const res = await app.inject({ method: "DELETE", url: `/api/accounts/${TARGET_ID}` });

    expect(res.statusCode).toBe(200);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledWith({ accountId: TARGET_ID });
    await app.close();
  });

  it("does NOT emit when caller is not admin (403)", async () => {
    const { app, accountLifecycle } = await buildApp("not-admin");
    const handler = vi.fn();
    accountLifecycle.on("deleted", handler);

    const res = await app.inject({ method: "DELETE", url: `/api/accounts/${TARGET_ID}` });

    expect(res.statusCode).toBe(403);
    expect(handler).not.toHaveBeenCalled();
    await app.close();
  });

  it("does NOT emit when admin tries to delete themselves (400)", async () => {
    const { app, accountLifecycle } = await buildApp(ADMIN_ID);
    const handler = vi.fn();
    accountLifecycle.on("deleted", handler);

    const res = await app.inject({ method: "DELETE", url: `/api/accounts/${ADMIN_ID}` });

    expect(res.statusCode).toBe(400);
    expect(handler).not.toHaveBeenCalled();
    await app.close();
  });
});

describe("GET /api/auth/me — demoEndpointsAvailable", () => {
  it("returns false when no demoEndpoints are configured", async () => {
    const { app } = await buildApp(ADMIN_ID, { demoEndpoints: [] });

    const res = await app.inject({ method: "GET", url: "/api/auth/me" });

    expect(res.statusCode).toBe(200);
    const body = res.json() as { demoEndpointsAvailable: boolean };
    expect(body.demoEndpointsAvailable).toBe(false);
    await app.close();
  });

  it("returns true when at least one demoEndpoint is configured", async () => {
    const { app } = await buildApp(ADMIN_ID, {
      demoEndpoints: [
        {
          label: "Demo: 2048",
          address: { host: "ssh.example.com", port: 22, username: "sw-2048" },
          agentForward: false,
        },
      ],
    });

    const res = await app.inject({ method: "GET", url: "/api/auth/me" });

    expect(res.statusCode).toBe(200);
    const body = res.json() as { demoEndpointsAvailable: boolean };
    expect(body.demoEndpointsAvailable).toBe(true);
    await app.close();
  });
});
