// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import type { FastifyInstance } from "fastify";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { ShellWatchDB } from "../db/connection.js";
import type { Config } from "../config/index.js";
import { registerCredentialRoutes } from "./credentials.js";
import { registerPasskeyInviteRoutes } from "./invite.js";
import { registerRegistrationRoutes } from "./registration.js";
import { registerSelfRegisterRoutes } from "./self-register.js";
import { registerStepUpRoutes } from "./stepup.js";

export type RateLimitConfig = Config["security"]["rateLimit"];

export interface WebAuthnRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  accountRepo: AccountRepository;
  rpId: string;
  trustedOrigins: string[];

  selfRegistrationEnabled: boolean;
  rateLimitConfig: RateLimitConfig;
}

export function registerWebAuthnRoutes(params: WebAuthnRoutesParams) {
  const { app, db, accountRepo, rpId, trustedOrigins, selfRegistrationEnabled, rateLimitConfig } =
    params;

  registerRegistrationRoutes({
    app,
    db,
    rpId,
    trustedOrigins,
    rateLimitConfig,
  });
  registerStepUpRoutes({
    app,
    db,
    rpId,
    trustedOrigins,
    rateLimitConfig,
  });
  registerCredentialRoutes({ app, db });
  registerPasskeyInviteRoutes({
    app,
    db,
    rpId,
    trustedOrigins,
    rateLimitConfig,
  });
  // Web login is no longer a JSON endpoint here — it's the Hydra passkey login
  // provider (src/hydra/routes.ts), reached via the SPA's authorization-code +
  // PKCE flow (#217). Only the anonymous self-registration / bootstrap routes
  // remain in this module.
  registerSelfRegisterRoutes({
    app,
    db,
    accountRepo,
    rpId,
    trustedOrigins,
    selfRegistrationEnabled,
    rateLimitConfig,
  });
}
