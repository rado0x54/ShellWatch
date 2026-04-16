import type { FastifyInstance } from "fastify";
import type Provider from "oidc-provider";
import type { ShellWatchDB } from "../db/connection.js";
import type { OAuthConfig } from "./config.js";
import { mountOAuthProvider } from "./mount.js";
import { createOAuthProvider } from "./provider.js";
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
}

/**
 * Single entry point for wiring OAuth into a Fastify app.
 *
 * Idempotency: calling this once at startup is sufficient. If `config.enabled`
 * is false, nothing is mounted and the function returns `null`.
 *
 * Ordering: this must be called *before* any route handlers that rely on the
 * OAuth verifier chain (PR 4 adds that). It is safe to call before routes
 * are registered because the `onRequest` hook used for mounting runs for
 * every request regardless of route-registration order.
 */
export async function registerOAuth(
  params: RegisterOAuthParams,
): Promise<RegisterOAuthResult | null> {
  if (!params.config.enabled) return null;

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
    db: params.db,
    config: params.config,
    signingKeyService,
  });

  mountOAuthProvider(params.app, provider, { prefix: OAUTH_PATH_PREFIX });

  params.app.log.info({ issuer, prefix: OAUTH_PATH_PREFIX }, "OAuth provider mounted");

  return { provider, signingKeyService };
}
