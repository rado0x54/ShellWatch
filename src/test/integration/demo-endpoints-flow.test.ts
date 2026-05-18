// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Integration tests for the virtual demo-endpoint plumbing.
 *
 * Covers the REST surface end-to-end:
 *   - GET /api/endpoints merges / excludes demo entries based on the account's
 *     showDemoEndpoints toggle.
 *   - PUT and DELETE /api/endpoints/:id reject `demo:*` virtual ids with 400.
 *   - POST /api/sessions resolves `demo:*` ids regardless of the toggle state
 *     (visibility hides them, but the connect path stays usable).
 *
 * Per-test Fastify rig — mirrors passkey-invite-flow.test.ts's approach so the
 * tests don't drag in the full buildApp() stack for an isolated surface.
 */
import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccountInfo, AccountRepository } from "../../db/repositories/account-repo.js";
import { InMemoryEndpointRepository } from "../../db/repositories/endpoint-repo.js";
import {
  createDemoEndpointsService,
  type DemoEndpointsService,
} from "../../demo-endpoints/index.js";
import { registerEndpointRoutes } from "../../server/routes/endpoints.js";
import { registerSessionRoutes } from "../../server/routes/sessions.js";
import type { TerminalManager } from "../../terminal/index.js";

const ACCOUNT_ID = "acct-test";

function buildAccountRepo(initial: Partial<AccountInfo> = {}): AccountRepository {
  const now = new Date().toISOString();
  const state: AccountInfo = {
    id: ACCOUNT_ID,
    name: "Test",
    isAdmin: false,
    enabled: true,
    maxSessions: 5,
    showDemoEndpoints: true,
    lastUsedAt: null,
    createdAt: now,
    updatedAt: now,
    ...initial,
  };
  return {
    async findById(id: string) {
      return id === ACCOUNT_ID ? state : null;
    },
    async findAll() {
      return [state];
    },
    async update(_id, data) {
      Object.assign(state, data);
    },
    touchLastUsed() {},
    flushLastUsed() {},
    getAdminAccountId() {
      return null;
    },
    setAdmin() {},
    isAdmin() {
      return false;
    },
    destroy() {},
  };
}

function buildTerminalManager(): TerminalManager {
  // Only the surfaces the routes under test actually touch — listSessions for
  // the delete-while-active check on real endpoints, and create() for the
  // session-open path. Everything else throws if reached so a test that
  // accidentally exercises an unmocked surface fails loudly rather than
  // hanging on a stub call.
  const created: { sessionId: string; endpointId: string; accountId: string }[] = [];
  const manager = {
    listSessions: vi.fn().mockReturnValue([]),
    create: vi.fn().mockImplementation(async (endpoint, accountId) => {
      const sessionId = `sess-${created.length + 1}`;
      created.push({ sessionId, endpointId: endpoint.id, accountId });
      return {
        sessionId,
        endpointId: endpoint.id,
        accountId,
        status: "open",
        createdAt: new Date(),
        lastActivityAt: new Date(),
        source: "ui",
      };
    }),
  } as unknown as TerminalManager;
  return manager;
}

interface Rig {
  app: FastifyInstance;
  endpointRepo: InMemoryEndpointRepository;
  demoEndpoints: DemoEndpointsService;
  accountRepo: AccountRepository;
  terminalManager: TerminalManager;
  demoEndpointId: string;
}

const DEMO_LABEL = "Demo: 2048";
const DEMO_HOST = "ssh.example.com";
const DEMO_PORT = 22;
const DEMO_USER = "sw-2048";

async function buildRig(opts: { showDemoEndpoints?: boolean } = {}): Promise<Rig> {
  const accountRepo = buildAccountRepo({
    showDemoEndpoints: opts.showDemoEndpoints ?? true,
  });
  const demoEndpoints = createDemoEndpointsService([
    {
      label: DEMO_LABEL,
      address: { host: DEMO_HOST, port: DEMO_PORT, username: DEMO_USER },
      agentForward: false,
    },
  ]);
  const endpointRepo = new InMemoryEndpointRepository([
    {
      id: "real-ep",
      accountId: ACCOUNT_ID,
      label: "Real Server",
      host: "real.example.com",
      port: 22,
      username: "ubuntu",
    },
  ]);
  const terminalManager = buildTerminalManager();

  const app = Fastify({ logger: false });
  app.decorateRequest("accountId", "");
  app.addHook("onRequest", async (request) => {
    request.accountId = ACCOUNT_ID;
  });
  registerEndpointRoutes({ app, endpointRepo, accountRepo, demoEndpoints, terminalManager });
  registerSessionRoutes({ app, endpointRepo, accountRepo, demoEndpoints, terminalManager });
  await app.ready();

  // Compute the demo id the same way the service does so we don't reach into
  // its internals to fetch it.
  const list = demoEndpoints.list(ACCOUNT_ID);
  const demoEndpointId = list[0].id;

  return { app, endpointRepo, demoEndpoints, accountRepo, terminalManager, demoEndpointId };
}

describe("GET /api/endpoints — demo merge", () => {
  let rig: Rig;
  afterEach(async () => {
    await rig.app.close();
  });

  it("includes demo entries when showDemoEndpoints is on", async () => {
    rig = await buildRig({ showDemoEndpoints: true });
    const res = await rig.app.inject({ method: "GET", url: "/api/endpoints" });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { endpoints: { id: string; isDemo: boolean }[] };
    const ids = body.endpoints.map((e) => e.id);
    expect(ids).toContain("real-ep");
    expect(ids).toContain(rig.demoEndpointId);
    const demoRow = body.endpoints.find((e) => e.id === rig.demoEndpointId)!;
    expect(demoRow.isDemo).toBe(true);
  });

  it("omits demo entries when showDemoEndpoints is off", async () => {
    rig = await buildRig({ showDemoEndpoints: false });
    const res = await rig.app.inject({ method: "GET", url: "/api/endpoints" });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { endpoints: { id: string }[] };
    const ids = body.endpoints.map((e) => e.id);
    expect(ids).toContain("real-ep");
    expect(ids.some((id) => id.startsWith("demo:"))).toBe(false);
  });
});

describe("mutation rejection on demo: ids", () => {
  let rig: Rig;
  beforeEach(async () => {
    rig = await buildRig();
  });
  afterEach(async () => {
    await rig.app.close();
  });

  it("PUT /api/endpoints/:id refuses a demo: id", async () => {
    const res = await rig.app.inject({
      method: "PUT",
      url: `/api/endpoints/${encodeURIComponent(rig.demoEndpointId)}`,
      payload: { label: "Should not stick" },
    });
    expect(res.statusCode).toBe(400);
    const body = res.json() as { error: string };
    expect(body.error).toMatch(/read-only/i);
  });

  it("DELETE /api/endpoints/:id refuses a demo: id", async () => {
    const res = await rig.app.inject({
      method: "DELETE",
      url: `/api/endpoints/${encodeURIComponent(rig.demoEndpointId)}`,
    });
    expect(res.statusCode).toBe(400);
    const body = res.json() as { error: string };
    expect(body.error).toMatch(/read-only/i);
  });
});

describe("POST /api/sessions — demo endpoint opens regardless of toggle", () => {
  let rig: Rig;
  afterEach(async () => {
    await rig.app.close();
  });

  it("opens a session against a demo: id when the toggle is on", async () => {
    rig = await buildRig({ showDemoEndpoints: true });
    const res = await rig.app.inject({
      method: "POST",
      url: "/api/sessions",
      payload: { endpointId: rig.demoEndpointId },
    });
    expect(res.statusCode).toBe(200);
    const create = rig.terminalManager.create as unknown as ReturnType<typeof vi.fn>;
    expect(create).toHaveBeenCalledTimes(1);
    const passed = create.mock.calls[0][0];
    expect(passed.host).toBe(DEMO_HOST);
    expect(passed.username).toBe(DEMO_USER);
  });

  it("opens a session against a demo: id even when the toggle is off (visibility-only)", async () => {
    rig = await buildRig({ showDemoEndpoints: false });
    const res = await rig.app.inject({
      method: "POST",
      url: "/api/sessions",
      payload: { endpointId: rig.demoEndpointId },
    });
    expect(res.statusCode).toBe(200);
    const create = rig.terminalManager.create as unknown as ReturnType<typeof vi.fn>;
    expect(create).toHaveBeenCalledTimes(1);
    const passed = create.mock.calls[0][0];
    expect(passed.host).toBe(DEMO_HOST);
  });

  it("404s for an unknown demo id", async () => {
    rig = await buildRig({ showDemoEndpoints: true });
    const res = await rig.app.inject({
      method: "POST",
      url: "/api/sessions",
      payload: { endpointId: "demo:doesnotexist" },
    });
    expect(res.statusCode).toBe(404);
  });
});
