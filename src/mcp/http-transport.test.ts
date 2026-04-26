import { EventEmitter } from "node:events";
import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import { InMemoryEndpointRepository } from "../db/repositories/endpoint-repo.js";
import { InMemorySshKeyRepository } from "../db/repositories/key-repo.js";
import { StubAccountRepository } from "../db/repositories/account-repo.js";
import { makeTestConfig } from "../test/helpers/test-config.js";
import type { TerminalManager } from "../terminal/terminal-manager.js";
import { registerMcpHttpTransport } from "./http-transport.js";

function createMockTerminalManager() {
  const emitter = new EventEmitter();
  return Object.assign(emitter, {
    create: vi.fn(),
    sendInput: vi.fn(),
    sendKeys: vi.fn(),
    readOutput: vi.fn(),
    resize: vi.fn(),
    listSessions: vi.fn().mockReturnValue([]),
    getSession: vi.fn(),
    close: vi.fn(),
    destroy: vi.fn(),
  }) as unknown as TerminalManager;
}

async function buildTestApp(opts: { stubAuth?: boolean } = {}) {
  const app = Fastify();
  if (opts.stubAuth) {
    // Stand-in for the bearer-gate: set request.accountId from a test header so
    // we can simulate cross-account requests against the same in-memory map.
    // Must run before the transport's onRequest hook, hence registered first.
    app.addHook("onRequest", async (request) => {
      const acct = request.headers["x-test-account"];
      request.accountId = typeof acct === "string" ? acct : "";
    });
  }
  await registerMcpHttpTransport({
    app,
    config: makeTestConfig(),
    terminalManager: createMockTerminalManager(),
    endpointRepo: new InMemoryEndpointRepository([]),
    keyRepo: new InMemorySshKeyRepository([]),
    accountRepo: new StubAccountRepository(),
  });
  return app;
}

describe("registerMcpHttpTransport", () => {
  it("returns 404 when a client presents an unknown mcp-session-id", async () => {
    const app = await buildTestApp();
    try {
      const res = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          "mcp-session-id": "stale-session-from-prior-instance",
        },
        payload: {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/list",
          params: {},
        },
      });

      expect(res.statusCode).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.jsonrpc).toBe("2.0");
      expect(body.error.code).toBe(-32001);
      expect(body.error.message).toMatch(/session not found/i);
    } finally {
      await app.close();
    }
  });

  it("returns 404 when a session id is presented by a different account (cross-account hijack)", async () => {
    const app = await buildTestApp({ stubAuth: true });
    try {
      const init = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          "x-test-account": "alice",
        },
        payload: {
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2024-11-05",
            capabilities: {},
            clientInfo: { name: "test", version: "0.0.0" },
          },
        },
      });
      expect(init.statusCode).toBe(200);
      const sessionId = init.headers["mcp-session-id"];
      expect(typeof sessionId).toBe("string");

      const hijack = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          "mcp-session-id": sessionId as string,
          "x-test-account": "bob",
        },
        payload: {
          jsonrpc: "2.0",
          id: 2,
          method: "tools/list",
          params: {},
        },
      });

      expect(hijack.statusCode).toBe(404);
      const body = JSON.parse(hijack.body);
      expect(body.error.code).toBe(-32001);
      expect(body.error.message).toMatch(/session not found/i);

      // Same id, original account → still works (proves we didn't break the legit path).
      const legit = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          "mcp-session-id": sessionId as string,
          "x-test-account": "alice",
        },
        payload: {
          jsonrpc: "2.0",
          id: 3,
          method: "tools/list",
          params: {},
        },
      });
      expect(legit.statusCode).toBe(200);
    } finally {
      await app.close();
    }
  });
});
