// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { and, eq } from "drizzle-orm";
import type { ShellWatchDB } from "../connection.js";
import { apiKeys } from "../schema.js";

export interface ApiKeyInfo {
  id: string;
  accountId: string;
  label: string;
  keyPrefix: string;
  scopes: string[];
  endpoints: string[] | null;
  enabled: boolean;
  createdAt: string;
}

// Public surface — every method is account-scoped. Route handlers, MCP tools,
// and any other request-context consumer take this narrower type so that an
// accidental cross-account read is a compile error rather than something a
// reviewer has to spot. See #136.
// Enabled-filter convention (load-bearing — do not unify these):
//   - findByHash      excludes rows where enabled=false (auth must reject revoked keys).
//   - findAllForAccount includes revoked rows (the UI shows a "revoked" badge).
export interface ApiKeyRepository {
  findAllForAccount(accountId: string): Promise<ApiKeyInfo[]>;
  /** True if a key with that id exists under that account (idempotent — already-revoked still returns true). */
  revokeForAccount(id: string, accountId: string): Promise<boolean>;
  create(data: {
    id: string;
    accountId: string;
    label: string;
    keyHash: string;
    keyPrefix: string;
    scopes: string[];
    endpoints?: string[];
  }): Promise<void>;
}

// Auth-only surface — exposed to the bearer gate and the OAuth callback, where
// the whole point of the lookup is to translate an opaque credential into an
// account identity. There is no caller-supplied accountId at the moment of the
// lookup because we are deriving it. Hand this handle out from DI root only.
export interface ApiKeyAuthRepository extends ApiKeyRepository {
  findByHash(hash: string): Promise<ApiKeyInfo | null>;
}

function parseRow(row: {
  id: string;
  accountId: string;
  label: string;
  keyPrefix: string;
  scopes: string;
  endpoints: string | null;
  enabled: boolean;
  createdAt: string;
}): ApiKeyInfo {
  return {
    ...row,
    scopes: JSON.parse(row.scopes) as string[],
    endpoints: row.endpoints ? (JSON.parse(row.endpoints) as string[]) : null,
  };
}

const API_KEY_COLUMNS = {
  id: apiKeys.id,
  accountId: apiKeys.accountId,
  label: apiKeys.label,
  keyPrefix: apiKeys.keyPrefix,
  scopes: apiKeys.scopes,
  endpoints: apiKeys.endpoints,
  enabled: apiKeys.enabled,
  createdAt: apiKeys.createdAt,
} as const;

export class DrizzleApiKeyRepository implements ApiKeyAuthRepository {
  constructor(private db: ShellWatchDB) {}

  async findByHash(hash: string): Promise<ApiKeyInfo | null> {
    const row = this.db
      .select(API_KEY_COLUMNS)
      .from(apiKeys)
      .where(eq(apiKeys.keyHash, hash))
      .get();
    if (!row || !row.enabled) return null;
    return parseRow(row);
  }

  async findAllForAccount(accountId: string): Promise<ApiKeyInfo[]> {
    const rows = this.db
      .select(API_KEY_COLUMNS)
      .from(apiKeys)
      .where(eq(apiKeys.accountId, accountId))
      .all();
    return rows.map(parseRow);
  }

  async create(data: {
    id: string;
    accountId: string;
    label: string;
    keyHash: string;
    keyPrefix: string;
    scopes: string[];
    endpoints?: string[];
  }): Promise<void> {
    this.db
      .insert(apiKeys)
      .values({
        id: data.id,
        accountId: data.accountId,
        label: data.label,
        keyHash: data.keyHash,
        keyPrefix: data.keyPrefix,
        scopes: JSON.stringify(data.scopes),
        endpoints: data.endpoints ? JSON.stringify(data.endpoints) : null,
        enabled: true,
        createdAt: new Date().toISOString(),
      })
      .run();
  }

  async revokeForAccount(id: string, accountId: string): Promise<boolean> {
    const result = this.db
      .update(apiKeys)
      .set({ enabled: false })
      .where(and(eq(apiKeys.id, id), eq(apiKeys.accountId, accountId)))
      .run();
    return result.changes > 0;
  }
}

export class InMemoryApiKeyRepository implements ApiKeyAuthRepository {
  private store: (ApiKeyInfo & { keyHash: string })[] = [];

  async findByHash(hash: string): Promise<ApiKeyInfo | null> {
    const key = this.store.find((k) => k.keyHash === hash && k.enabled);
    if (!key) return null;
    const { keyHash: _keyHash, ...rest } = key;
    return rest;
  }

  async findAllForAccount(accountId: string): Promise<ApiKeyInfo[]> {
    return this.store
      .filter((k) => k.accountId === accountId)
      .map(({ keyHash: _keyHash, ...rest }) => rest);
  }

  async create(data: {
    id: string;
    accountId: string;
    label: string;
    keyHash: string;
    keyPrefix: string;
    scopes: string[];
    endpoints?: string[];
  }): Promise<void> {
    this.store.push({
      id: data.id,
      accountId: data.accountId,
      label: data.label,
      keyHash: data.keyHash,
      keyPrefix: data.keyPrefix,
      scopes: data.scopes,
      endpoints: data.endpoints ?? null,
      enabled: true,
      createdAt: new Date().toISOString(),
    });
  }

  async revokeForAccount(id: string, accountId: string): Promise<boolean> {
    const key = this.store.find((k) => k.id === id && k.accountId === accountId);
    if (!key) return false;
    key.enabled = false;
    return true;
  }
}
