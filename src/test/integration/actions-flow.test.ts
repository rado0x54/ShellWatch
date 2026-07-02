// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Integration coverage for the human-in-the-loop signing-approval routes
 * (`/api/actions/*`) — the security-critical resolve/deny path that had no
 * integration test (#225 item 3). These routes are only mounted when an
 * actionStore + wsChannel are supplied, so the test wires its own and seeds
 * pending actions directly.
 *
 * The resolve endpoint does not verify the signature itself (the SSH server does
 * that downstream against the sk-* pubkey); it gates on the UV bit when the
 * action requires UV, then hands the payload to the store. So a crafted
 * authenticatorData with the right flag byte is sufficient here.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, onTestFailed } from "vitest";
import { PendingActionStore, WebSocketChannel } from "../../pending-action/index.js";
import type { PendingAction, SignRequestContext } from "../../pending-action/index.js";
import {
  createTestLog,
  startTestApp,
  startTestSshServer,
  type TestAppServer,
  type TestLog,
  type TestSshServer,
} from "../helpers/index.js";

const CONTEXT: SignRequestContext = {
  source: "endpoint-auth",
  endpointLabel: "Test Server",
  endpointAddress: "testuser@127.0.0.1:22",
  trigger: { kind: "ui" },
};

/** authenticatorData with the flag byte at offset 32; UV bit (0x04) optionally set. */
function authData(uv: boolean): string {
  const b = Buffer.alloc(37);
  b[32] = uv ? 0x05 : 0x01; // UP always; UV conditionally
  return b.toString("base64url");
}

describe("Actions (signing approval) flow", () => {
  let log: TestLog;
  let sshServer: TestSshServer;
  let app: TestAppServer;
  let store: PendingActionStore;

  beforeAll(async () => {
    log = createTestLog();
    sshServer = await startTestSshServer(log);
    store = new PendingActionStore();
    app = await startTestApp(sshServer, log, {
      actionStore: store,
      wsChannel: new WebSocketChannel(),
    });
  });

  afterAll(async () => {
    await app?.close();
    await sshServer?.close();
  });

  afterEach(() => {
    onTestFailed(() => log.dump());
    log.clear();
  });

  function seedWebauthn(accountId = app.accountId): {
    action: PendingAction;
    resolved: () => boolean;
  } {
    let didResolve = false;
    const action = store.create({
      type: "webauthn-sign",
      accountId,
      credentialId: "cred-under-test",
      challenge: "Y2hhbGxlbmdl",
      rpId: "localhost",
      userVerification: "required",
      redirectTo: "/terminal/sess_abc",
      context: CONTEXT,
      resolve: () => {
        didResolve = true;
      },
      reject: () => {},
    });
    return { action, resolved: () => didResolve };
  }

  function seedKeyApprove(): { action: PendingAction; resolved: () => boolean } {
    let didResolve = false;
    const action = store.create({
      type: "key-approve",
      accountId: app.accountId,
      keyLabel: "Test Key",
      keyFingerprint: "SHA256:testfingerprint",
      redirectTo: "/terminal/sess_key",
      context: CONTEXT,
      resolve: () => {
        didResolve = true;
      },
      reject: () => {},
    });
    return { action, resolved: () => didResolve };
  }

  const resolveBody = (uv: boolean) => ({
    authenticatorData: authData(uv),
    signature: "c2ln",
    clientDataJSON: "Y2Rq",
  });

  const post = (path: string, body?: unknown) => {
    // Omit the JSON content-type on bodyless POSTs — Fastify 400s on an empty
    // body when application/json is declared.
    const init: RequestInit =
      body === undefined
        ? { method: "POST" }
        : {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(body),
          };
    return app.fetch(path, init);
  };

  describe("GET /api/actions/:id", () => {
    it("returns the action view for the owning account", async () => {
      const { action } = seedWebauthn();
      const res = await app.fetch(`/api/actions/${action.id}`);
      expect(res.status).toBe(200);
      const view = await res.json();
      expect(view).toMatchObject({
        id: action.id,
        type: "webauthn-sign",
        status: "pending",
        credentialId: "cred-under-test",
        rpId: "localhost",
      });
      expect(view.resolve).toBeUndefined(); // callbacks stripped by toActionView
    });

    it("404 for an unknown action", async () => {
      const res = await app.fetch(`/api/actions/act_does_not_exist`);
      expect(res.status).toBe(404);
    });

    it("403 for an action owned by another account", async () => {
      const { action } = seedWebauthn("someone-else-account");
      const res = await app.fetch(`/api/actions/${action.id}`);
      expect(res.status).toBe(403);
    });
  });

  describe("POST /api/actions/:id/resolve", () => {
    it("resolves a key-approve action with no payload", async () => {
      const { action, resolved } = seedKeyApprove();
      const res = await post(`/api/actions/${action.id}/resolve`);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ redirectTo: "/terminal/sess_key" });
      expect(resolved()).toBe(true);
    });

    it("400 when webauthn fields are missing", async () => {
      const { action } = seedWebauthn();
      const res = await post(`/api/actions/${action.id}/resolve`, { signature: "only" });
      expect(res.status).toBe(400);
    });

    it("400 when UV is required but the UV bit is not set", async () => {
      const { action, resolved } = seedWebauthn();
      const res = await post(`/api/actions/${action.id}/resolve`, resolveBody(false));
      expect(res.status).toBe(400);
      expect((await res.json()).error).toMatch(/user verification/i);
      expect(resolved()).toBe(false);
    });

    it("resolves a webauthn-sign action when UV is set, and is idempotent-guarded", async () => {
      const { action, resolved } = seedWebauthn();
      const res = await post(`/api/actions/${action.id}/resolve`, resolveBody(true));
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ redirectTo: "/terminal/sess_abc" });
      expect(resolved()).toBe(true);

      // Second resolve → 409 (no longer pending).
      const again = await post(`/api/actions/${action.id}/resolve`, resolveBody(true));
      expect(again.status).toBe(409);
    });
  });

  describe("POST /api/actions/:id/deny", () => {
    it("denies a pending action, then 409 on repeat", async () => {
      const { action } = seedWebauthn();
      const res = await post(`/api/actions/${action.id}/deny`);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ status: "denied" });

      const again = await post(`/api/actions/${action.id}/deny`);
      expect(again.status).toBe(409);
    });
  });
});
