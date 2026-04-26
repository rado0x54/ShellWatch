import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import Fastify from "fastify";
import type { FastifyInstance } from "fastify";
import { PendingActionStore } from "./store.js";
import { WebSocketChannel } from "./ws-channel.js";
import { registerActionRoutes } from "../server/routes/actions.js";
import type { KeyApproveAction, WebAuthnSignAction } from "./types.js";

const testAccountId = "test-account";

type WebAuthnParams = Omit<WebAuthnSignAction, "id" | "status" | "createdAt" | "expiresAt">;
type KeyApproveParams = Omit<KeyApproveAction, "id" | "status" | "createdAt" | "expiresAt">;

function makeWebAuthnParams(overrides?: Partial<WebAuthnParams>): WebAuthnParams {
  return {
    type: "webauthn-sign",
    accountId: testAccountId,
    context: {
      source: "agent-proxy",
      sourceIp: "127.0.0.1",
      apiKeyLabel: "Test Key",
      apiKeyPrefix: "sw_test",
    },
    credentialId: "cred-1",
    challenge: "dGVzdA==",
    rpId: "localhost",
    passkeyLabel: "YubiKey",
    userVerification: "required",
    resolve: vi.fn(),
    reject: vi.fn(),
    ...overrides,
  };
}

function makeKeyApproveParams(overrides?: Partial<KeyApproveParams>): KeyApproveParams {
  return {
    type: "key-approve",
    accountId: testAccountId,
    context: {
      source: "endpoint-auth",
      endpointLabel: "Prod",
      endpointAddress: "user@host:22",
      trigger: { kind: "ui", sourceIp: "127.0.0.1" },
    },
    keyLabel: "Test Key",
    keyFingerprint: "SHA256:abc123",
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
    // Simulate the production auth gate: the gate sets request.accountId for
    // authenticated requests and 401s anything that reaches a handler without
    // one. The route handlers themselves rely on that invariant and do not
    // re-check, so the test gate must enforce it too.
    app.decorateRequest("accountId", "");
    app.addHook("onRequest", async (request, reply) => {
      const accountHeader = request.headers["x-test-account"] as string | undefined;
      if (!accountHeader) {
        reply.status(401).send({ error: "Authentication required" });
        return;
      }
      request.accountId = accountHeader;
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
    const action = actionStore.create(makeWebAuthnParams());
    const res = await fetch(url(`/api/actions/${action.id}`));
    expect(res.status).toBe(401);
  });

  it("GET returns 404 for unknown action", async () => {
    const res = await fetch(url("/api/actions/nonexistent"), { headers: authHeaders() });
    expect(res.status).toBe(404);
  });

  it("GET returns 403 for wrong account", async () => {
    const action = actionStore.create(makeWebAuthnParams());
    const res = await fetch(url(`/api/actions/${action.id}`), {
      headers: authHeaders("other-account"),
    });
    expect(res.status).toBe(403);
  });

  it("GET returns action data for correct account", async () => {
    const action = actionStore.create(makeWebAuthnParams());
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
    const action = actionStore.create(makeWebAuthnParams());
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
    const action = actionStore.create(makeWebAuthnParams());
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
    const action = actionStore.create(makeWebAuthnParams());
    const res = await fetch(url(`/api/actions/${action.id}/resolve`), {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ authenticatorData: "AAAA" }),
    });
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error).toMatch(/Missing required fields/);
  });

  // 37-byte authenticatorData with UV flag set (byte 32 = 0x04)
  const authDataUV = (() => {
    const buf = Buffer.alloc(37);
    buf[32] = 0x04;
    return buf.toString("base64url");
  })();

  it("resolve completes a pending action", async () => {
    const resolve = vi.fn();
    const action = actionStore.create(makeWebAuthnParams({ resolve }));

    const res = await fetch(url(`/api/actions/${action.id}/resolve`), {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({
        authenticatorData: authDataUV,
        signature: "BBBB",
        clientDataJSON: '{"type":"webauthn.get"}',
      }),
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.redirectTo).toBeUndefined();
    expect(resolve).toHaveBeenCalled();
  });

  it("resolve rejects when UV flag is not set and action requires UV", async () => {
    const action = actionStore.create(makeWebAuthnParams());
    const authDataNoUV = Buffer.alloc(37).toString("base64url"); // flags byte = 0x00
    const res = await fetch(url(`/api/actions/${action.id}/resolve`), {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({
        authenticatorData: authDataNoUV,
        signature: "BBBB",
        clientDataJSON: "{}",
      }),
    });
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error).toMatch(/user verification/i);
  });

  it("resolve accepts UV=0 when action userVerification is 'discouraged'", async () => {
    const resolve = vi.fn();
    const action = actionStore.create(
      makeWebAuthnParams({ userVerification: "discouraged", resolve }),
    );
    const authDataNoUV = Buffer.alloc(37).toString("base64url");
    const res = await fetch(url(`/api/actions/${action.id}/resolve`), {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({
        authenticatorData: authDataNoUV,
        signature: "BBBB",
        clientDataJSON: '{"type":"webauthn.get"}',
      }),
    });
    expect(res.status).toBe(200);
    expect(resolve).toHaveBeenCalled();
  });

  it("resolve returns 409 for already-resolved action", async () => {
    const action = actionStore.create(makeWebAuthnParams());
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
    const action = actionStore.create(makeWebAuthnParams());
    const res = await fetch(url(`/api/actions/${action.id}/deny`), { method: "POST" });
    expect(res.status).toBe(401);
  });

  it("deny returns 403 for wrong account", async () => {
    const action = actionStore.create(makeWebAuthnParams());
    const res = await fetch(url(`/api/actions/${action.id}/deny`), {
      method: "POST",
      headers: authHeaders("other-account"),
    });
    expect(res.status).toBe(403);
  });

  it("deny rejects a pending action", async () => {
    const reject = vi.fn();
    const action = actionStore.create(makeWebAuthnParams({ reject }));

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
    const action = actionStore.create(makeWebAuthnParams());
    actionStore.deny(action.id);

    const res = await fetch(url(`/api/actions/${action.id}/deny`), {
      method: "POST",
      headers: authHeaders(),
    });
    expect(res.status).toBe(409);
  });

  // --- key-approve action type ---

  it("GET returns key-approve action data", async () => {
    const action = actionStore.create(makeKeyApproveParams());
    const res = await fetch(url(`/api/actions/${action.id}`), { headers: authHeaders() });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.type).toBe("key-approve");
    expect(data.keyLabel).toBe("Test Key");
    expect(data.keyFingerprint).toBe("SHA256:abc123");
  });

  it("resolve completes a key-approve action with empty body", async () => {
    const resolve = vi.fn();
    const action = actionStore.create(makeKeyApproveParams({ resolve }));

    const res = await fetch(url(`/api/actions/${action.id}/resolve`), {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: "{}",
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.redirectTo).toBeUndefined();
    expect(resolve).toHaveBeenCalled();
  });

  it("deny rejects a key-approve action", async () => {
    const reject = vi.fn();
    const action = actionStore.create(makeKeyApproveParams({ reject }));

    const res = await fetch(url(`/api/actions/${action.id}/deny`), {
      method: "POST",
      headers: authHeaders(),
    });
    expect(res.status).toBe(200);
    expect(reject).toHaveBeenCalled();
  });
});
