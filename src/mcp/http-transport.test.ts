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

async function buildTestApp() {
  const app = Fastify();
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
});
