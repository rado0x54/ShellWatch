import { randomBytes } from "node:crypto";
import type { BearerScope } from "../server/auth/bearer-gate.js";

/**
 * What `/oauth/token` will turn into the access token when this code is
 * redeemed.
 *
 * - `existing` carries a key the user pasted and we pre-validated at
 *   authorize-POST time. The token endpoint just returns it.
 * - `create` is a pending request to mint a fresh key. We deliberately
 *   do NOT write the key to the DB at authorize-POST — only after PKCE
 *   has verified at the token endpoint — so abandoned or failed flows
 *   don't leave orphan credentials behind. `scopes` is the (deduped,
 *   sorted) set of internal scopes the minted key will carry — derived
 *   from the requested OAuth scope param + resource indicator.
 */
export type AuthCodePending =
  | { kind: "existing"; apiKey: string }
  | { kind: "create"; accountId: string; label: string; scopes: BearerScope[] };

export interface StoredAuthCode {
  codeChallenge: string;
  codeChallengeMethod: "S256";
  pending: AuthCodePending;
  redirectUri: string;
  clientId: string;
  expiresAt: number;
}

export type AuthCodeEntry = Omit<StoredAuthCode, "expiresAt">;

export interface AuthCodeStore {
  create(entry: AuthCodeEntry): string;
  consume(code: string): StoredAuthCode | null;
  size(): number;
  destroy(): void;
}

export interface CreateAuthCodeStoreOptions {
  ttlMs?: number;
  sweepIntervalMs?: number;
  now?: () => number;
}

export function createAuthCodeStore(options: CreateAuthCodeStoreOptions = {}): AuthCodeStore {
  const ttlMs = options.ttlMs ?? 60_000;
  const sweepIntervalMs = options.sweepIntervalMs ?? 30_000;
  const now = options.now ?? Date.now;
  const map = new Map<string, StoredAuthCode>();

  const sweep = setInterval(() => {
    const t = now();
    for (const [code, entry] of map) {
      if (entry.expiresAt < t) map.delete(code);
    }
  }, sweepIntervalMs);
  sweep.unref();

  return {
    create(entry) {
      const code = randomBytes(32).toString("base64url");
      map.set(code, { ...entry, expiresAt: now() + ttlMs });
      return code;
    },
    consume(code) {
      const entry = map.get(code);
      if (!entry) return null;
      map.delete(code);
      if (entry.expiresAt < now()) return null;
      return entry;
    },
    size() {
      return map.size;
    },
    destroy() {
      clearInterval(sweep);
      map.clear();
    },
  };
}
