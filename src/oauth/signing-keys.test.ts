import { resolve } from "node:path";
import { randomBytes } from "node:crypto";
import Database from "better-sqlite3";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import { SignJWT, jwtVerify, importJWK } from "jose";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createSigningKeyService, deriveEncryptionKey } from "./signing-keys.js";

type AnyDb = BetterSQLite3Database<Record<string, never>>;

function setupDb(): { db: AnyDb; close: () => void } {
  const sqlite = new Database(":memory:");
  sqlite.pragma("journal_mode = WAL");
  const db = drizzle(sqlite, { schema: {} });
  migrate(db, { migrationsFolder: resolve(import.meta.dirname, "../../drizzle") });
  return {
    db,
    close: () => sqlite.close(),
  };
}

describe("SigningKeyService", () => {
  let setup: ReturnType<typeof setupDb>;
  let encryptionKey: Buffer;

  beforeEach(() => {
    setup = setupDb();
    encryptionKey = randomBytes(32);
  });

  afterEach(() => {
    setup.close();
  });

  describe("construction", () => {
    it("rejects encryption keys that aren't 32 bytes", () => {
      expect(() =>
        createSigningKeyService({ db: setup.db as never, encryptionKey: randomBytes(16) }),
      ).toThrow(/must be 32 bytes/);
    });
  });

  describe("getSigner", () => {
    it("generates and persists a fresh Ed25519 key on first call", async () => {
      const svc = createSigningKeyService({ db: setup.db as never, encryptionKey });
      const signer = await svc.getSigner();

      expect(signer.alg).toBe("EdDSA");
      expect(signer.kid).toBeTruthy();
      expect(signer.privateJwk.kty).toBe("OKP");
      expect(signer.privateJwk.crv).toBe("Ed25519");
      expect(signer.privateJwk.d).toBeTruthy(); // private component
      expect(signer.publicJwk.d).toBeUndefined(); // public should not have `d`
      expect(signer.publicJwk.x).toBeTruthy();
    });

    it("returns the same key on subsequent calls (no regeneration)", async () => {
      const svc = createSigningKeyService({ db: setup.db as never, encryptionKey });
      const first = await svc.getSigner();
      const second = await svc.getSigner();
      expect(second.kid).toBe(first.kid);
      expect(second.privateJwk.d).toBe(first.privateJwk.d);
    });

    it("persists across service instances", async () => {
      const first = await createSigningKeyService({
        db: setup.db as never,
        encryptionKey,
      }).getSigner();
      const second = await createSigningKeyService({
        db: setup.db as never,
        encryptionKey,
      }).getSigner();
      expect(second.kid).toBe(first.kid);
    });

    it("fails to decrypt when the encryption key changes (at-rest encryption works)", async () => {
      await createSigningKeyService({ db: setup.db as never, encryptionKey }).getSigner();
      const rotatedKey = randomBytes(32);
      const otherSvc = createSigningKeyService({
        db: setup.db as never,
        encryptionKey: rotatedKey,
      });
      await expect(otherSvc.getSigner()).rejects.toThrow();
    });
  });

  describe("listActivePublicJwks", () => {
    it("returns a JWKS object suitable for a /jwks endpoint", async () => {
      const svc = createSigningKeyService({ db: setup.db as never, encryptionKey });
      const signer = await svc.getSigner();
      const jwks = await svc.listActivePublicJwks();

      expect(jwks.keys.length).toBe(1);
      expect(jwks.keys[0]!.kid).toBe(signer.kid);
      expect(jwks.keys[0]!.alg).toBe("EdDSA");
      expect(jwks.keys[0]!.d).toBeUndefined(); // public only
    });

    it("returns an empty JWKS when no keys exist yet", async () => {
      const svc = createSigningKeyService({ db: setup.db as never, encryptionKey });
      const jwks = await svc.listActivePublicJwks();
      expect(jwks.keys).toEqual([]);
    });
  });

  describe("listActivePrivateJwks", () => {
    it("returns JWKs with private material", async () => {
      const svc = createSigningKeyService({ db: setup.db as never, encryptionKey });
      await svc.getSigner();
      const jwks = await svc.listActivePrivateJwks();
      expect(jwks.length).toBe(1);
      expect(jwks[0]!.d).toBeTruthy();
    });
  });

  describe("end-to-end: the generated key actually signs and verifies", () => {
    it("round-trips a JWT via jose", async () => {
      const svc = createSigningKeyService({ db: setup.db as never, encryptionKey });
      const signer = await svc.getSigner();

      const privateKey = await importJWK(signer.privateJwk, "EdDSA");
      const publicKey = await importJWK(signer.publicJwk, "EdDSA");

      const token = await new SignJWT({ hello: "world" })
        .setProtectedHeader({ alg: "EdDSA", kid: signer.kid })
        .setIssuedAt()
        .setExpirationTime("1m")
        .sign(privateKey);

      const { payload } = await jwtVerify(token, publicKey);
      expect(payload.hello).toBe("world");
    });
  });

  describe("ensureSigningKey — concurrency & idempotency", () => {
    it("is idempotent across many parallel callers on a cold DB", async () => {
      const svc = createSigningKeyService({ db: setup.db as never, encryptionKey });

      // All 10 callers should see exactly one key; no two parallel
      // generate-and-insert races may create distinct rows.
      const results = await Promise.all(Array.from({ length: 10 }, () => svc.ensureSigningKey()));

      const kids = new Set(results.map((k) => k.kid));
      expect(kids.size).toBe(1);

      // And the table should hold a single row.
      const publicJwks = await svc.listActivePublicJwks();
      expect(publicJwks.keys.length).toBe(1);
    });

    it("getSigner is an alias for ensureSigningKey", async () => {
      const svc = createSigningKeyService({ db: setup.db as never, encryptionKey });
      const viaEnsure = await svc.ensureSigningKey();
      const viaGetSigner = await svc.getSigner();
      expect(viaGetSigner.kid).toBe(viaEnsure.kid);
    });
  });
});

describe("deriveEncryptionKey", () => {
  it("produces a 32-byte key", () => {
    const key = deriveEncryptionKey("some-secret-value-for-ShellWatch");
    expect(key.length).toBe(32);
  });

  it("is deterministic for the same input", () => {
    const a = deriveEncryptionKey("secret-42");
    const b = deriveEncryptionKey("secret-42");
    expect(a.equals(b)).toBe(true);
  });

  it("produces different keys for different secrets", () => {
    const a = deriveEncryptionKey("secret-42");
    const b = deriveEncryptionKey("secret-43");
    expect(a.equals(b)).toBe(false);
  });

  it("rejects empty secrets", () => {
    expect(() => deriveEncryptionKey("")).toThrow(/non-empty/);
  });
});
