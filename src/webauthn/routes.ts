import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { ShellWatchDB } from "../db/connection.js";
import type { Config } from "../config/index.js";
import { registerCredentialRoutes } from "./credentials.js";
import { registerLoginRoutes } from "./login.js";
import { registerRegistrationRoutes } from "./registration.js";
import { registerSelfRegisterRoutes } from "./self-register.js";

/**
 * Passkey login and self-register call this after a successful WebAuthn
 * verify. The OAuth module provides the concrete implementation — see
 * `src/oauth/ui-session.ts`. Kept as a plain function interface here so
 * the passkey code never imports from `src/oauth`.
 */
export type OnLoginSuccess = (
  request: FastifyRequest,
  reply: FastifyReply,
  input: { accountId: string },
) => Promise<void>;

export type RateLimitConfig = Config["security"]["rateLimit"];

export interface WebAuthnRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  accountRepo: AccountRepository;
  rpId: string;
  trustedOrigins: string[];

  /**
   * Invoked after a successful login or self-register. If omitted, the
   * routes still verify the passkey but no session is issued — useful
   * for test harnesses that assert pure WebAuthn behaviour.
   */
  onLoginSuccess?: OnLoginSuccess;
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
    onLoginSuccess,
    selfRegistrationEnabled,
    rateLimitConfig,
  } = params;

  registerRegistrationRoutes({
    app,
    db,
    accountRepo,
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
    onLoginSuccess,
    rateLimitConfig,
  });
  registerSelfRegisterRoutes({
    app,
    db,
    accountRepo,
    rpId,
    trustedOrigins,
    onLoginSuccess,
    selfRegistrationEnabled,
    rateLimitConfig,
  });
}
