// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";
import fastifyRateLimit from "@fastify/rate-limit";
import { StubAccountRepository } from "../db/repositories/account-repo.js";
import { rateLimitDefaults } from "../config/schema.js";
import { registerSelfRegisterRoutes } from "./self-register.js";
import type { ShellWatchDB } from "../db/connection.js";

// Mock hasPasskeys to control the guard without needing a real DB
vi.mock("../db/repositories/credential-queries.js", () => ({
  hasPasskeys: vi.fn(() => false),
  deduplicateLabel: vi.fn((_db: unknown, _accountId: string, label: string) => label),
}));

import { hasPasskeys } from "../db/repositories/credential-queries.js";

describe("self-register guard", () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    app = Fastify({ logger: false });
    await app.register(fastifyRateLimit, { global: false });
    vi.mocked(hasPasskeys).mockReturnValue(false);
  });

  afterEach(async () => {
    await app.close();
    vi.restoreAllMocks();
  });

  function registerRoutes(selfRegistrationEnabled: boolean) {
    registerSelfRegisterRoutes({
      app,
      db: {} as ShellWatchDB,
      accountRepo: new StubAccountRepository(),
      rpId: "localhost",
      trustedOrigins: ["http://localhost"],
      selfRegistrationEnabled,
      rateLimitConfig: rateLimitDefaults,
    });
  }

  function postRegister() {
    return app.inject({
      method: "POST",
      url: "/api/auth/register",
      payload: { name: "test", challengeId: "fake", credential: {} },
    });
  }

  describe("selfRegistrationEnabled = false", () => {
    it("allows registration when no passkeys exist (bootstrap)", async () => {
      vi.mocked(hasPasskeys).mockReturnValue(false);
      registerRoutes(false);
      const res = await postRegister();
      // Should pass the guard — will fail later on challenge validation, not 403
      expect(res.statusCode).not.toBe(403);
    });

    it("blocks registration when passkeys exist", async () => {
      vi.mocked(hasPasskeys).mockReturnValue(true);
      registerRoutes(false);
      const res = await postRegister();
      expect(res.statusCode).toBe(403);
      expect(res.json()).toEqual({ error: "Self-registration is disabled" });
    });
  });

  describe("selfRegistrationEnabled = true", () => {
    it("allows registration when passkeys exist", async () => {
      vi.mocked(hasPasskeys).mockReturnValue(true);
      registerRoutes(true);
      const res = await postRegister();
      // Should pass the guard — will fail later on challenge validation, not 403
      expect(res.statusCode).not.toBe(403);
    });

    it("allows registration when no passkeys exist", async () => {
      vi.mocked(hasPasskeys).mockReturnValue(false);
      registerRoutes(true);
      const res = await postRegister();
      expect(res.statusCode).not.toBe(403);
    });
  });
});
