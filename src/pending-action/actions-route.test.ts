import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import Fastify from "fastify";
import type { FastifyInstance } from "fastify";
import { PendingActionStore } from "./store.js";
import { WebSocketChannel } from "./ws-channel.js";
import { registerActionRoutes } from "../server/routes/actions.js";
import type { CreateActionParams } from "./types.js";

const testAccountId = "test-account";

function makeActionParams(overrides?: Partial<CreateActionParams>): CreateActionParams {
  return {
    type: "webauthn-sign",
    accountId: testAccountId,
    context: { source: "agent-proxy", sourceIp: "127.0.0.1", apiKeyPrefix: "sw_test" },
    credentialId: "cred-1",
    challenge: "dGVzdA==",
    rpId: "localhost",
    passkeyLabel: "YubiKey",
    resolve: vi.fn(),
    reject: vi.fn(),
    ...overrides,
  };
}

describe("action routes", () => {
  let app: FastifyInstance;
  let actionStore: PendingActionStore;
  let wsChannel: WebSocketChannel;

  beforeAll(async () => {
    actionStore = new PendingActionStore();
    wsChannel = new WebSocketChannel();

    app = Fastify({ logger: false });
    // Simulate auth by decorating accountId
    app.decorateRequest("accountId", null);
    app.addHook("onRequest", async (request) => {
      const accountHeader = request.headers["x-test-account"] as string | undefined;
      if (accountHeader) {
        request.accountId = accountHeader;
      }
    });

    registerActionRoutes({ app, actionStore, wsChannel });
    await app.listen({ port: 0, host: "127.0.0.1" });
  });

  afterAll(async () => {
    actionStore.destroy();
    await app.close();
  });

  function url(path: string): string {
    const addr = app.server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    return `http://127.0.0.1:${port}${path}`;
  }

  function authHeaders(accountId = testAccountId): Record<string, string> {
    return { "x-test-account": accountId };
  }

  // --- GET /api/actions/:actionId ---

  it("GET returns 401 without auth", async () => {
    const action = actionStore.create(makeActionParams());
    const res = await fetch(url(`/api/actions/${action.id}`));
    expect(res.status).toBe(401);
  });

  it("GET returns 404 for unknown action", async () => {
    const res = await fetch(url("/api/actions/nonexistent"), { headers: authHeaders() });
    expect(res.status).toBe(404);
  });

  it("GET returns 403 for wrong account", async () => {
    const action = actionStore.create(makeActionParams());
    const res = await fetch(url(`/api/actions/${action.id}`), {
      headers: authHeaders("other-account"),
    });
    expect(res.status).toBe(403);
  });

  it("GET returns action data for correct account", async () => {
    const action = actionStore.create(makeActionParams());
    const res = await fetch(url(`/api/actions/${action.id}`), { headers: authHeaders() });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.id).toBe(action.id);
    expect(data.status).toBe("pending");
    expect(data.context.source).toBe("agent-proxy");
    // resolve/reject should not be serialized
    expect(data.resolve).toBeUndefined();
    expect(data.reject).toBeUndefined();
  });

  // --- POST /api/actions/:actionId/resolve ---

  it("resolve returns 401 without auth", async () => {
    const action = actionStore.create(makeActionParams());
    const res = await fetch(url(`/api/actions/${action.id}/resolve`), { method: "POST" });
    expect(res.status).toBe(401);
  });

  it("resolve returns 404 for unknown action", async () => {
    const res = await fetch(url("/api/actions/nonexistent/resolve"), {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({
        authenticatorData: "AAAA",
        signature: "BBBB",
        clientDataJSON: "{}",
      }),
    });
    expect(res.status).toBe(404);
  });

  it("resolve returns 403 for wrong account", async () => {
    const action = actionStore.create(makeActionParams());
    const res = await fetch(url(`/api/actions/${action.id}/resolve`), {
      method: "POST",
      headers: { ...authHeaders("other-account"), "Content-Type": "application/json" },
      body: JSON.stringify({
        authenticatorData: "AAAA",
        signature: "BBBB",
        clientDataJSON: "{}",
      }),
    });
    expect(res.status).toBe(403);
  });

  it("resolve returns 400 for missing body fields", async () => {
    const action = actionStore.create(makeActionParams());
    const res = await fetch(url(`/api/actions/${action.id}/resolve`), {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ authenticatorData: "AAAA" }),
    });
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error).toMatch(/Missing required fields/);
  });

  it("resolve completes a pending action", async () => {
    const resolve = vi.fn();
    const action = actionStore.create(makeActionParams({ resolve }));

    const res = await fetch(url(`/api/actions/${action.id}/resolve`), {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({
        authenticatorData: "AAAA",
        signature: "BBBB",
        clientDataJSON: '{"type":"webauthn.get"}',
      }),
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe("completed");
    expect(resolve).toHaveBeenCalled();
  });

  it("resolve returns 409 for already-resolved action", async () => {
    const action = actionStore.create(makeActionParams());
    // Resolve it first
    actionStore.resolve(action.id, {
      requestId: action.id,
      authenticatorData: Buffer.from("a"),
      signature: Buffer.from("b"),
      clientDataJSON: "{}",
    });

    const res = await fetch(url(`/api/actions/${action.id}/resolve`), {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({
        authenticatorData: "AAAA",
        signature: "BBBB",
        clientDataJSON: "{}",
      }),
    });
    expect(res.status).toBe(409);
  });

  // --- POST /api/actions/:actionId/deny ---

  it("deny returns 401 without auth", async () => {
    const action = actionStore.create(makeActionParams());
    const res = await fetch(url(`/api/actions/${action.id}/deny`), { method: "POST" });
    expect(res.status).toBe(401);
  });

  it("deny returns 403 for wrong account", async () => {
    const action = actionStore.create(makeActionParams());
    const res = await fetch(url(`/api/actions/${action.id}/deny`), {
      method: "POST",
      headers: authHeaders("other-account"),
    });
    expect(res.status).toBe(403);
  });

  it("deny rejects a pending action", async () => {
    const reject = vi.fn();
    const action = actionStore.create(makeActionParams({ reject }));

    const res = await fetch(url(`/api/actions/${action.id}/deny`), {
      method: "POST",
      headers: authHeaders(),
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe("denied");
    expect(reject).toHaveBeenCalled();
  });

  it("deny returns 409 for already-denied action", async () => {
    const action = actionStore.create(makeActionParams());
    actionStore.deny(action.id);

    const res = await fetch(url(`/api/actions/${action.id}/deny`), {
      method: "POST",
      headers: authHeaders(),
    });
    expect(res.status).toBe(409);
  });
});
