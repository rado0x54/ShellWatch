import type { FastifyInstance } from "fastify";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { ShellWatchDB } from "../db/connection.js";
import { registerCredentialRoutes } from "./credentials.js";
import { registerLoginRoutes } from "./login.js";
import { registerRegistrationRoutes } from "./registration.js";
import { registerSelfRegisterRoutes } from "./self-register.js";

export interface SessionConfig {
  secret: string;
  ttlSeconds: number;
}

export interface WebAuthnRoutesParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  accountRepo: AccountRepository;
  rpId: string;
  trustedOrigins: string[];
  basePath?: string;
  sessionConfig?: SessionConfig;
}

export function registerWebAuthnRoutes(params: WebAuthnRoutesParams) {
  const { app, db, accountRepo, rpId, trustedOrigins, basePath = "", sessionConfig } = params;

  registerRegistrationRoutes({ app, db, accountRepo, rpId, trustedOrigins, basePath });
  registerCredentialRoutes({ app, db, basePath });
  registerLoginRoutes({ app, db, accountRepo, rpId, trustedOrigins, basePath, sessionConfig });
  registerSelfRegisterRoutes({
    app,
    db,
    accountRepo,
    rpId,
    trustedOrigins,
    basePath,
    sessionConfig,
  });
}
