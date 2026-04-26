import type { FastifyInstance } from "fastify";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { ShellWatchDB } from "../db/connection.js";
import type { Config } from "../config/index.js";
import { registerCredentialRoutes } from "./credentials.js";
import { registerLoginRoutes } from "./login.js";
import { registerRegistrationRoutes } from "./registration.js";
import { registerSelfRegisterRoutes } from "./self-register.js";

export interface SessionConfig {
  secret: string;
  ttlSeconds: number;
}

export type RateLimitConfig = Config["security"]["rateLimit"];

export interface WebAuthnRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  accountRepo: AccountRepository;
  rpId: string;
  trustedOrigins: string[];

  sessionConfig?: SessionConfig;
  selfRegistrationEnabled: boolean;
  rateLimitConfig: RateLimitConfig;
}

export function registerWebAuthnRoutes(params: WebAuthnRoutesParams) {
  const {
    app,
    db,
    accountRepo,
    rpId,
    trustedOrigins,

    sessionConfig,
    selfRegistrationEnabled,
    rateLimitConfig,
  } = params;

  registerRegistrationRoutes({
    app,
    db,
    rpId,
    trustedOrigins,
    rateLimitConfig,
  });
  registerCredentialRoutes({ app, db });
  registerLoginRoutes({
    app,
    db,
    accountRepo,
    rpId,
    trustedOrigins,
    sessionConfig,
    rateLimitConfig,
  });
  registerSelfRegisterRoutes({
    app,
    db,
    accountRepo,
    rpId,
    trustedOrigins,
    sessionConfig,
    selfRegistrationEnabled,
    rateLimitConfig,
  });
}
