// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import type { SigningRequestsRepository } from "../../audit/index.js";
import { registerAuditRoutes } from "./audit.js";

const ACCOUNT_ID = "acct_a";

function fakeRepo(): SigningRequestsRepository {
  return {
    insertCreated: vi.fn(),
    recordResolution: vi.fn(),
    list: vi.fn().mockReturnValue({ rows: [], nextCursor: null }),
    getById: vi.fn().mockReturnValue(null),
  };
}

async function buildApp(repo: SigningRequestsRepository) {
  const app = Fastify({ logger: false });
  app.decorateRequest("accountId", "");
  app.addHook("onRequest", async (request) => {
    request.accountId = ACCOUNT_ID;
  });
  registerAuditRoutes({ app, signingRequestsRepo: repo });
  return app;
}

describe("GET /api/audit/signings filter validation", () => {
  it("400s on an invalid source value", async () => {
    const repo = fakeRepo();
    const app = await buildApp(repo);
    try {
      const res = await app.inject({ method: "GET", url: "/api/audit/signings?source=bogus" });
      expect(res.statusCode).toBe(400);
      expect(res.json()).toEqual({ error: "invalid source filter" });
      expect(repo.list).not.toHaveBeenCalled();
    } finally {
      await app.close();
    }
  });

  it("400s on an invalid outcome value", async () => {
    const repo = fakeRepo();
    const app = await buildApp(repo);
    try {
      const res = await app.inject({ method: "GET", url: "/api/audit/signings?outcome=maybe" });
      expect(res.statusCode).toBe(400);
      expect(res.json()).toEqual({ error: "invalid outcome filter" });
      expect(repo.list).not.toHaveBeenCalled();
    } finally {
      await app.close();
    }
  });

  it("forwards valid filters to the repo (account-scoped)", async () => {
    const repo = fakeRepo();
    const app = await buildApp(repo);
    try {
      const res = await app.inject({
        method: "GET",
        url: "/api/audit/signings?source=agent-proxy&outcome=approved&from=2026-01-01T00:00:00Z&to=2026-01-31T23:59:59Z&limit=10",
      });
      expect(res.statusCode).toBe(200);
      expect(repo.list).toHaveBeenCalledTimes(1);
      const [accountIdArg, filtersArg, pagingArg] = vi.mocked(repo.list).mock.calls[0]!;
      expect(accountIdArg).toBe(ACCOUNT_ID);
      expect(filtersArg).toEqual({
        source: "agent-proxy",
        outcome: "approved",
        from: "2026-01-01T00:00:00Z",
        to: "2026-01-31T23:59:59Z",
      });
      expect(pagingArg).toEqual({ cursor: undefined, limit: 10 });
    } finally {
      await app.close();
    }
  });

  it("treats missing filters as undefined and accepts the request", async () => {
    const repo = fakeRepo();
    const app = await buildApp(repo);
    try {
      const res = await app.inject({ method: "GET", url: "/api/audit/signings" });
      expect(res.statusCode).toBe(200);
      const [, filtersArg] = vi.mocked(repo.list).mock.calls[0]!;
      expect(filtersArg).toEqual({
        source: undefined,
        outcome: undefined,
        from: undefined,
        to: undefined,
      });
    } finally {
      await app.close();
    }
  });
});
