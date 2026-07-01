// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * Shared thin-app harness for WebAuthn ceremony tests. Builds a per-test Fastify
 * app wired with a real in-memory SQLite DB, the bearer gate, and the webauthn +
 * hydra routes — the minimum needed to run the actual registration/assertion
 * crypto. Used by both webauthn-ceremony-flow.test.ts (behavior) and
 * golden-webauthn.test.ts (fixture capture) so the setup lives in one place.
 */
import fastifyRateLimit from "@fastify/rate-limit";
import Fastify, { type FastifyInstance, type LightMyRequestResponse } from "fastify";
import { rateLimitDefaults } from "../../config/schema.js";
import { createDatabase, type DatabaseConnection } from "../../db/connection.js";
import { runMigrations } from "../../db/migrate.js";
import { StubAccountRepository } from "../../db/repositories/account-repo.js";
import { createBearerResolver } from "../../hydra/bearer-resolver.js";
import { registerHydraRoutes } from "../../hydra/routes.js";
import { registerBearerGate } from "../../server/auth/bearer-gate.js";
import { registerWebAuthnRoutes } from "../../webauthn/routes.js";
import { createFakeAuthenticator, type FakeAuthenticator } from "./fake-authenticator.js";
import type { FakeHydraAdmin } from "./fake-hydra.js";
import { makeTestBearer } from "./test-bearer.js";
import { makeTestConfig } from "./test-config.js";

export const RP_ID = "localhost";
export const ORIGIN = "http://localhost";

export interface WebauthnTestApp {
  app: FastifyInstance;
  conn: DatabaseConnection;
  admin: FakeHydraAdmin;
  bearerFor: (accountId: string) => string;
}

export async function makeWebauthnApp(): Promise<WebauthnTestApp> {
  const conn = createDatabase(":memory:");
  runMigrations(conn.db);

  const app = Fastify({ logger: false });
  app.decorateRequest("accountId", "");
  app.decorateRequest("apiKey", null);
  await app.register(fastifyRateLimit, { global: false });

  const accountRepo = new StubAccountRepository();
  const config = makeTestConfig();
  const { admin, bearerFor } = makeTestBearer();
  registerBearerGate({
    app,
    resolveBearer: createBearerResolver({ admin, cacheTtlMs: 0 }),
    accountRepo,
    config,
    agentProxyEnabled: false,
  });
  registerWebAuthnRoutes({
    app,
    db: conn.db,
    accountRepo,
    admin,
    rpId: RP_ID,
    trustedOrigins: [ORIGIN],
    selfRegistrationEnabled: false, // fresh db has no passkeys → bootstrap still allowed
    rateLimitConfig: rateLimitDefaults,
  });
  registerHydraRoutes({
    app,
    config,
    db: conn.db,
    accountRepo,
    admin,
    rpId: RP_ID,
    trustedOrigins: [ORIGIN],
    agentProxyEnabled: false,
  });
  await app.ready();
  return { app, conn, admin, bearerFor };
}

export function injectPost(
  app: FastifyInstance,
  url: string,
  payload: Record<string, unknown>,
  opts: { auth?: string; stepUp?: string } = {},
): Promise<LightMyRequestResponse> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.auth) headers.authorization = opts.auth;
  if (opts.stepUp) headers["x-shellwatch-stepup-token"] = opts.stepUp;
  return app.inject({ method: "POST", url, headers, payload });
}

/**
 * Run the self-register (bootstrap) ceremony. Pass a `fake` to control the
 * keypair/credential id (golden fixtures need a deterministic one); defaults to
 * a fresh random authenticator.
 */
export async function enroll(
  app: FastifyInstance,
  fake: FakeAuthenticator = createFakeAuthenticator({ rpId: RP_ID, origin: ORIGIN }),
): Promise<{ fake: FakeAuthenticator; accountId: string }> {
  const optRes = await injectPost(app, "/api/auth/register/options", { name: "User" });
  const { challenge, challengeId } = optRes.json();
  const res = await injectPost(app, "/api/auth/register", {
    name: "User",
    challengeId,
    credential: fake.register(challenge),
  });
  if (res.statusCode !== 200) throw new Error(`enroll failed (${res.statusCode}): ${res.body}`);
  return { fake, accountId: res.json().accountId };
}

/** Mint a step-up token for `action` using an already-enrolled authenticator. */
export async function stepUp(
  app: FastifyInstance,
  auth: string,
  fake: FakeAuthenticator,
  action: string,
): Promise<string> {
  const optRes = await injectPost(app, "/api/webauthn/stepup/options", { action }, { auth });
  const { challenge, challengeId } = optRes.json();
  const verRes = await injectPost(
    app,
    "/api/webauthn/stepup/verify",
    { challengeId, credential: fake.authenticate(challenge), action },
    { auth },
  );
  if (verRes.statusCode !== 200)
    throw new Error(`stepUp failed (${verRes.statusCode}): ${verRes.body}`);
  return verRes.json().stepUpToken;
}
