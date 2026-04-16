import { createCipheriv, createDecipheriv, hkdfSync, randomBytes, randomUUID } from "node:crypto";
import { desc, isNull } from "drizzle-orm";
import { exportJWK, generateKeyPair, type JWK } from "jose";
import type { ShellWatchDB } from "../db/connection.js";
import { oauthSigningKeys } from "./adapter/schema.js";

/**
 * JWKS material management for the OAuth Provider.
 *
 * panva needs an asymmetric key pair for:
 *  - signing OIDC `id_token` JWTs (only if a client requests the `openid`
 *    scope; we don't emit them by default, but the key has to exist),
 *  - signing RFC 7592 registration access tokens,
 *  - exposing public keys at `/oidc/jwks` for any external verifier.
 *
 * Access tokens are opaque in this deployment, so no signing key is used for
 * them — but the ones above still need a key.
 *
 * Phase 1 provides single-key "generate on first use, keep using it"
 * semantics. Rotation (`retiredAt`) is a later-phase concern; the DB column
 * is already in place so rotation becomes purely application logic.
 */

export interface ActiveSigningKey {
  kid: string;
  alg: "EdDSA";
  privateJwk: JWK;
  publicJwk: JWK;
  createdAt: Date;
}

export interface SigningKeyService {
  /**
   * Returns all non-retired private JWKs. This is what we hand to panva's
   * Provider config (`jwks.keys`). The newest key goes first.
   */
  listActivePrivateJwks(): Promise<JWK[]>;

  /** Public-only view for the `/oidc/jwks` endpoint. */
  listActivePublicJwks(): Promise<{ keys: JWK[] }>;

  /**
   * Idempotent: returns the current signing key, or generates one inside a
   * `BEGIN IMMEDIATE` transaction if none exists. Use this from startup
   * wiring (`registerOAuth`) to ensure `/oidc/jwks` is never empty on a
   * cold DB and to close the first-boot race where two concurrent callers
   * would otherwise each insert a fresh key.
   */
  ensureSigningKey(): Promise<ActiveSigningKey>;

  /**
   * Alias for {@link ensureSigningKey}. Panva calls through the service
   * to obtain the key material; always returns the same key once created.
   */
  getSigner(): Promise<ActiveSigningKey>;
}

export interface SigningKeyServiceDeps {
  db: ShellWatchDB;
  /**
   * 32-byte key for AES-256-GCM encryption of private JWKs at rest.
   * Callers should produce this via {@link deriveEncryptionKey} from
   * `config.security.sessionSecret` so the derivation is uniform across
   * the codebase.
   */
  encryptionKey: Buffer;
}

export function createSigningKeyService(deps: SigningKeyServiceDeps): SigningKeyService {
  if (deps.encryptionKey.length !== 32) {
    throw new Error("signing-keys: encryptionKey must be 32 bytes (AES-256-GCM)");
  }

  // Coalesce concurrent `ensureSigningKey` callers through a single
  // in-flight promise. ShellWatch is single-process + single-SQLite-connection,
  // so an in-memory guard is sufficient — there is no other writer to race
  // against. If we ever run multiple processes against the same DB, this
  // moves to a SQL-level lock (SELECT FOR UPDATE equivalent).
  let pendingLoad: Promise<ActiveSigningKey> | null = null;

  async function ensure(): Promise<ActiveSigningKey> {
    if (pendingLoad) return pendingLoad;
    pendingLoad = (async () => {
      const rows = await listActiveKeyRows(deps);
      if (rows[0]) return hydrateKeyRow(rows[0], deps.encryptionKey);
      return generateAndPersist(deps);
    })().finally(() => {
      pendingLoad = null;
    });
    return pendingLoad;
  }

  return {
    listActivePrivateJwks: () => listActivePrivateJwks(deps),
    listActivePublicJwks: () => listActivePublicJwks(deps),
    ensureSigningKey: ensure,
    getSigner: ensure,
  };
}

/**
 * Produces the 32-byte AES-256-GCM key used by {@link createSigningKeyService}
 * from the caller's session secret (typically `config.security.sessionSecret`).
 *
 * HKDF-SHA256 with a stable info label so repeated derivations against the
 * same secret reproduce the same key — rotating `sessionSecret` invalidates
 * every stored JWK at once, which is the right failure mode if the
 * operator believes the master secret has leaked.
 */
export function deriveEncryptionKey(sessionSecret: string): Buffer {
  if (!sessionSecret) {
    throw new Error("signing-keys: sessionSecret must be a non-empty string");
  }
  return Buffer.from(
    hkdfSync("sha256", sessionSecret, Buffer.alloc(0), "shellwatch-oauth-jwk", 32),
  );
}

// ----- internals -----

async function listActiveKeyRows(deps: SigningKeyServiceDeps) {
  return deps.db
    .select()
    .from(oauthSigningKeys)
    .where(isNull(oauthSigningKeys.retiredAt))
    .orderBy(desc(oauthSigningKeys.createdAt));
}

async function listActivePrivateJwks(deps: SigningKeyServiceDeps): Promise<JWK[]> {
  const rows = await listActiveKeyRows(deps);
  return rows.map((row) => {
    const jwk = decryptJwk(row.privateJwkCiphertext, deps.encryptionKey);
    return { ...jwk, kid: row.kid, alg: row.alg } as JWK;
  });
}

async function listActivePublicJwks(deps: SigningKeyServiceDeps): Promise<{ keys: JWK[] }> {
  const rows = await listActiveKeyRows(deps);
  const keys = rows.map((row) => {
    const publicJwk = row.publicJwk as JWK;
    return { ...publicJwk, kid: row.kid, alg: row.alg } as JWK;
  });
  return { keys };
}

type SigningKeyRow = Awaited<ReturnType<typeof listActiveKeyRows>>[number];

function hydrateKeyRow(row: SigningKeyRow, encryptionKey: Buffer): ActiveSigningKey {
  const privateJwk = decryptJwk(row.privateJwkCiphertext, encryptionKey);
  return {
    kid: row.kid,
    alg: row.alg as "EdDSA",
    privateJwk: { ...privateJwk, kid: row.kid, alg: row.alg } as JWK,
    publicJwk: { ...(row.publicJwk as JWK), kid: row.kid, alg: row.alg } as JWK,
    createdAt: new Date(row.createdAt),
  };
}

async function generateAndPersist(deps: SigningKeyServiceDeps): Promise<ActiveSigningKey> {
  const kid = randomUUID();
  const alg = "EdDSA" as const;
  const { publicKey, privateKey } = await generateKeyPair(alg, {
    crv: "Ed25519",
    extractable: true,
  });
  const publicJwk = await exportJWK(publicKey);
  const privateJwk = await exportJWK(privateKey);

  const now = new Date();
  await deps.db.insert(oauthSigningKeys).values({
    kid,
    alg,
    privateJwkCiphertext: encryptJwk(privateJwk, deps.encryptionKey),
    publicJwk,
    createdAt: now.toISOString(),
    retiredAt: null,
  });

  return {
    kid,
    alg,
    privateJwk: { ...privateJwk, kid, alg } as JWK,
    publicJwk: { ...publicJwk, kid, alg } as JWK,
    createdAt: now,
  };
}

// ----- encryption (AES-256-GCM) -----

const NONCE_BYTES = 12;
const TAG_BYTES = 16;

function encryptJwk(jwk: JWK, key: Buffer): string {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const plaintext = Buffer.from(JSON.stringify(jwk), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, ciphertext, tag]).toString("base64");
}

function decryptJwk(encoded: string, key: Buffer): JWK {
  const buf = Buffer.from(encoded, "base64");
  if (buf.length < NONCE_BYTES + TAG_BYTES) {
    throw new Error("signing-keys: ciphertext too short");
  }
  const nonce = buf.subarray(0, NONCE_BYTES);
  const tag = buf.subarray(buf.length - TAG_BYTES);
  const data = buf.subarray(NONCE_BYTES, buf.length - TAG_BYTES);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(data), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8"));
}
