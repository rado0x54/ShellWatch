// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Integration tests for the /demo/authorized-keys lookup endpoint.
 *
 * What this exercises:
 *   - End-to-end request → DB lookup → text/plain response
 *   - IP allowlist scoped to /demo/authorized-keys
 *   - Optional shared-secret header check
 *   - 200 + empty body for misses (sshd treats non-2xx as a soft error)
 *   - 400 when required querystring params are missing
 *
 * Built on a thin per-test Fastify app, mirroring passkey-invite-flow's pattern,
 * rather than full buildApp() — keeps the test focused and avoids dragging in
 * SSH / MCP / WebSocket infrastructure for an unrelated endpoint.
 */
import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createDatabase, type DatabaseConnection } from "../../db/connection.js";
import { runMigrations } from "../../db/migrate.js";
import { CREDENTIAL_STATE } from "../../db/repositories/credential-queries.js";
import { accounts, webauthnCredentials } from "../../db/schema.js";
import {
  createDemoAuthorizedKeysService,
  DEMO_AUTHORIZED_KEYS_PATH,
  registerDemoAuthorizedKeysRoute,
} from "../../demo-authorized-keys/index.js";
import { registerIpAllowlist } from "../../server/auth/ip-allowlist.js";
import { fingerprintFromAuthorizedKeys } from "../../webauthn/fingerprint.js";

const KEY =
  "webauthn-sk-ecdsa-sha2-nistp256@openssh.com AAAALndlYmF1dGgtZXhhbXBsZS1rZXktQQAAAAhuaXN0cDI1NgAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlsb2NhbGhvc3Q=";
const KEY_TYPE = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";

interface TestApp {
  app: FastifyInstance;
  conn: DatabaseConnection;
  fingerprint: string;
}

async function makeTestApp(
  opts: { sharedSecret?: string; allowedNetworks?: string[] } = {},
): Promise<TestApp> {
  const conn = createDatabase(":memory:");
  runMigrations(conn.db);

  const now = new Date().toISOString();
  conn.db
    .insert(accounts)
    .values({ id: "acc-1", name: "Alice", createdAt: now, updatedAt: now })
    .run();
  const fp = fingerprintFromAuthorizedKeys(KEY);
  if (!fp) throw new Error("test setup: fingerprint missing");
  conn.db
    .insert(webauthnCredentials)
    .values({
      id: "cred-1",
      accountId: "acc-1",
      credentialId: "webauthn-cred-1",
      publicKey: Buffer.alloc(0),
      label: "Alice's Passkey",
      state: CREDENTIAL_STATE.active,
      revoked: false,
      publicKeyOpenSsh: KEY,
      fingerprint: fp,
      createdAt: now,
    })
    .run();

  const app = Fastify({ logger: false });
  // /demo/authorized-keys has no global IP gate by default; tests opt in by
  // passing allowedNetworks. Default "0.0.0.0/0, ::/0" keeps simple tests
  // open without exercising the allowlist path.
  registerIpAllowlist(app, opts.allowedNetworks ?? ["0.0.0.0/0", "::/0"], [
    DEMO_AUTHORIZED_KEYS_PATH,
  ]);
  const service = createDemoAuthorizedKeysService({ db: conn.db, cacheTtlMs: 1000 });
  registerDemoAuthorizedKeysRoute({ app, service, sharedSecret: opts.sharedSecret });
  await app.ready();

  return { app, conn, fingerprint: fp };
}

describe("GET /demo/authorized-keys", () => {
  let ctx: TestApp;

  afterEach(async () => {
    await ctx.app.close();
    ctx.conn.close();
  });

  it("returns the OpenSSH line for a known (type, fingerprint)", async () => {
    ctx = await makeTestApp();
    const res = await ctx.app.inject({
      method: "GET",
      url: `${DEMO_AUTHORIZED_KEYS_PATH}?user=sw-snake&type=${encodeURIComponent(KEY_TYPE)}&fingerprint=${encodeURIComponent(ctx.fingerprint)}`,
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toMatch(/^text\/plain/);
    expect(res.body).toContain(KEY);
    expect(res.body).toContain("shellwatch:acc-1/webauthn-cred-1");
    expect(res.body.endsWith("\n")).toBe(true);
  });

  it("returns 200 + empty body on miss (clean deny for sshd)", async () => {
    ctx = await makeTestApp();
    const res = await ctx.app.inject({
      method: "GET",
      url: `${DEMO_AUTHORIZED_KEYS_PATH}?user=sw-snake&type=${encodeURIComponent(KEY_TYPE)}&fingerprint=SHA256:not-a-real-fingerprint`,
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toBe("");
  });

  it("400s when required params are missing", async () => {
    ctx = await makeTestApp();
    const res = await ctx.app.inject({
      method: "GET",
      url: `${DEMO_AUTHORIZED_KEYS_PATH}?user=sw-snake`,
    });
    expect(res.statusCode).toBe(400);
  });

  it("blocks non-allowlisted source IPs with 403", async () => {
    // Allow only a single off-loopback address — Fastify inject uses 127.0.0.1
    // as the synthetic source so the request should be rejected.
    ctx = await makeTestApp({ allowedNetworks: ["10.10.10.10/32"] });
    const res = await ctx.app.inject({
      method: "GET",
      url: `${DEMO_AUTHORIZED_KEYS_PATH}?type=${encodeURIComponent(KEY_TYPE)}&fingerprint=${encodeURIComponent(ctx.fingerprint)}`,
    });
    expect(res.statusCode).toBe(403);
  });

  describe("with sharedSecret", () => {
    const SECRET = "demo-shared-secret-1234567890";

    it("accepts a request bearing the matching secret", async () => {
      ctx = await makeTestApp({ sharedSecret: SECRET });
      const res = await ctx.app.inject({
        method: "GET",
        url: `${DEMO_AUTHORIZED_KEYS_PATH}?type=${encodeURIComponent(KEY_TYPE)}&fingerprint=${encodeURIComponent(ctx.fingerprint)}`,
        headers: { authorization: `Bearer ${SECRET}` },
      });
      expect(res.statusCode).toBe(200);
      expect(res.body).toContain(KEY);
    });

    it("403s when the bearer is missing", async () => {
      ctx = await makeTestApp({ sharedSecret: SECRET });
      const res = await ctx.app.inject({
        method: "GET",
        url: `${DEMO_AUTHORIZED_KEYS_PATH}?type=${encodeURIComponent(KEY_TYPE)}&fingerprint=${encodeURIComponent(ctx.fingerprint)}`,
      });
      expect(res.statusCode).toBe(403);
    });

    it("403s when the bearer doesn't match", async () => {
      ctx = await makeTestApp({ sharedSecret: SECRET });
      const res = await ctx.app.inject({
        method: "GET",
        url: `${DEMO_AUTHORIZED_KEYS_PATH}?type=${encodeURIComponent(KEY_TYPE)}&fingerprint=${encodeURIComponent(ctx.fingerprint)}`,
        headers: { authorization: "Bearer wrong-secret" },
      });
      expect(res.statusCode).toBe(403);
    });
  });
});

beforeEach(() => {
  // satisfy vitest's beforeEach requirement (no per-test prep needed)
});
