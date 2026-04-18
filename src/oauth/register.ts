import type { FastifyInstance } from "fastify";
import type Provider from "oidc-provider";
import type { ShellWatchDB } from "../db/connection.js";
import type { Config } from "../config/index.js";
import type { AccountRepository } from "../db/repositories/account-repo.js";
import type { OAuthConfig } from "./config.js";
import { createFirstPartyTokenMinter, type FirstPartyTokenMinter } from "./first-party.js";
import { registerInteractionRoutes } from "./interactions/routes.js";
import { mountOAuthProvider } from "./mount.js";
import { createOAuthProvider } from "./provider.js";
import { registerDcrRateLimit } from "./rate-limit.js";
import {
  createSigningKeyService,
  deriveEncryptionKey,
  type SigningKeyService,
} from "./signing-keys.js";

export interface RegisterOAuthParams {
  app: FastifyInstance;
  db: ShellWatchDB;
  config: OAuthConfig;
  /**
   * Absolute external base URL of the ShellWatch deployment
   * (e.g. `https://shellwatch.example.com` — no trailing slash, no `/oidc`).
   * The provider's issuer becomes `${baseUrl}/oidc`.
   */
  baseUrl: string;
  /**
   * Session secret from `config.security.sessionSecret` (or equivalent).
   * HKDF-derived into the 32-byte AES-256-GCM key that encrypts stored
   * private JWKs at rest. Passing the raw secret here (rather than a
   * pre-derived key) keeps the derivation pinned to a single place.
   */
  sessionSecret: string;
  /**
   * Passed through to the interaction routes so they can reuse the
   * Web UI's passkey infrastructure (rpId, trustedOrigins, account
   * lookup). Kept as a dep rather than re-reading from `config` to
   * keep this module's interface narrow.
   */
  accountRepo: AccountRepository;
  /** Full security config — used for rpId + trusted origins. */
  security: Config["security"];
}

const OAUTH_PATH_PREFIX = "/oidc";

export interface RegisterOAuthResult {
  /**
   * The configured panva Provider. Exposed so later PRs (first-party token
   * minter, verifier chain) can reach its model constructors, and so tests
   * can introspect client registration. Production callers that only want
   * to mount OAuth routes can ignore the return value.
   */
  provider: Provider;
  /**
   * The signing key service tied to the same DB / encryption key as the
   * provider. Kept so callers can read the active JWKS without having to
   * reconstruct the service.
   */
  signingKeyService: SigningKeyService;
  /**
   * First-party token minter bound to this provider. The Web UI's
   * passkey-login handler delegates here to turn a successful WebAuthn
   * verify into an opaque access + refresh token pair.
   */
  minter: FirstPartyTokenMinter;
}

/**
 * Single entry point for wiring OAuth into a Fastify app.
 *
 * Idempotency: calling this once at startup is sufficient.
 *
 * Ordering: this must be called *before* any route handlers that rely on
 * the OAuth verifier chain. It is safe to call before routes are
 * registered because the `onRequest` hook used for mounting runs for
 * every request regardless of route-registration order.
 */
export async function registerOAuth(params: RegisterOAuthParams): Promise<RegisterOAuthResult> {
  // Normalise a possible trailing slash on the external URL so the issuer
  // is e.g. "https://host/oidc" rather than "https://host//oidc".
  const normalizedBaseUrl = params.baseUrl.replace(/\/$/, "");
  const issuer = `${normalizedBaseUrl}${OAUTH_PATH_PREFIX}`;

  const signingKeyService = createSigningKeyService({
    db: params.db,
    encryptionKey: deriveEncryptionKey(params.sessionSecret),
  });

  // Seed the JWK before the provider is constructed; otherwise the Provider
  // starts with an empty `jwks.keys` array and panva's first attempt to sign
  // anything throws.
  await signingKeyService.ensureSigningKey();

  const provider = await createOAuthProvider({
    issuer,
    baseUrl: normalizedBaseUrl,
    db: params.db,
    config: params.config,
    signingKeyService,
  });

  // DCR rate limit must be attached BEFORE panva's mount hook. Fastify
  // runs `onRequest` hooks in registration order; panva's hook hijacks
  // and writes the response synchronously, so any rate-limit hook
  // registered after it arrives too late to short-circuit. When DCR is
  // disabled this whole block is skipped.
  if (params.config.dynamicClientRegistration === "open") {
    registerDcrRateLimit(params.app, {
      perMinute: params.config.registrationRateLimitPerMinute,
    });
  }

  mountOAuthProvider(params.app, provider, { prefix: OAUTH_PATH_PREFIX });

  registerInteractionRoutes({
    app: params.app,
    provider,
    db: params.db,
    accountRepo: params.accountRepo,
    rpId: params.security.rpId,
    trustedOrigins: params.security.trustedWebauthnOrigins,
  });

  params.app.log.info({ issuer, prefix: OAUTH_PATH_PREFIX }, "OAuth provider mounted");

  const minter = createFirstPartyTokenMinter(provider, {
    accessTokenSeconds: params.config.accessTokenTtlSeconds,
  });

  return { provider, signingKeyService, minter };
}
