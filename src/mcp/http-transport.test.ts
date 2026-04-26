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
    // Strict: a missing header is a programming error, not "" — prod's
    // bearer-gate either populates a real id or 401s, and we don't want this
    // stub to silently mask a future regression where two requests both end up
    // with empty accountIds and the cross-account check trivially passes.
    app.addHook("onRequest", async (request) => {
      const acct = request.headers["x-test-account"];
      if (typeof acct !== "string" || acct.length === 0) {
        throw new Error("test stub requires non-empty x-test-account header");
      }
      request.accountId = acct;
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

const initPayload = {
  jsonrpc: "2.0" as const,
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "test", version: "0.0.0" },
  },
};

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

  // Cross-account hijack must respond identically to a stale session id (no
  // oracle). Parameterized over every method the hook intercepts: POST (RPC),
  // DELETE (per-spec session termination — silent cross-account close would be
  // a real DoS primitive), GET (SSE stream open).
  describe.each(["POST", "DELETE", "GET"] as const)(
    "cross-account session-id presented via %s",
    (method) => {
      it("returns the same 404 as a stale session id", async () => {
        const app = await buildTestApp({ stubAuth: true });
        try {
          // Establish a real session as alice.
          const init = await app.inject({
            method: "POST",
            url: "/mcp",
            headers: {
              "content-type": "application/json",
              accept: "application/json, text/event-stream",
              "x-test-account": "alice",
            },
            payload: initPayload,
          });
          expect(init.statusCode).toBe(200);
          const sessionId = init.headers["mcp-session-id"];
          expect(typeof sessionId).toBe("string");

          const hijackHeaders = {
            "content-type": "application/json",
            accept: "application/json, text/event-stream",
            "x-test-account": "bob",
            "mcp-session-id": sessionId as string,
          };
          const staleHeaders = { ...hijackHeaders, "mcp-session-id": "definitely-not-a-real-id" };
          // POST is the only method that carries a JSON-RPC body; GET/DELETE
          // pre-empt at the hook level so payload is irrelevant — but Fastify
          // inject still needs a valid shape.
          const payload =
            method === "POST" ? { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} } : "";

          const stale = await app.inject({ method, url: "/mcp", headers: staleHeaders, payload });
          const hijack = await app.inject({ method, url: "/mcp", headers: hijackHeaders, payload });

          // Both 404, with byte-identical bodies and content-type, so an
          // attacker cannot distinguish "your id is wrong" from "your id is
          // right but belongs to someone else".
          expect(stale.statusCode).toBe(404);
          expect(hijack.statusCode).toBe(404);
          expect(hijack.body).toBe(stale.body);
          expect(hijack.headers["content-type"]).toBe(stale.headers["content-type"]);
        } finally {
          await app.close();
        }
      });
    },
  );

  it("legit owner can still reuse the session after a cross-account 404", async () => {
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
        payload: initPayload,
      });
      const sessionId = init.headers["mcp-session-id"] as string;

      // Hijack attempt by bob.
      const hijack = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          "x-test-account": "bob",
          "mcp-session-id": sessionId,
        },
        payload: { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
      });
      expect(hijack.statusCode).toBe(404);

      // Alice's session is untouched.
      const legit = await app.inject({
        method: "POST",
        url: "/mcp",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          "x-test-account": "alice",
          "mcp-session-id": sessionId,
        },
        payload: { jsonrpc: "2.0", id: 3, method: "tools/list", params: {} },
      });
      expect(legit.statusCode).toBe(200);
    } finally {
      await app.close();
    }
  });
});
