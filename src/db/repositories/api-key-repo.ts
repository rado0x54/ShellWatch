import { eq } from "drizzle-orm";
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

export interface ApiKeyRepository {
  findByHash(hash: string): Promise<ApiKeyInfo | null>;
  findAll(): Promise<ApiKeyInfo[]>;
  create(data: {
    id: string;
    accountId: string;
    label: string;
    keyHash: string;
    keyPrefix: string;
    scopes: string[];
    endpoints?: string[];
  }): Promise<void>;
  revoke(id: string): Promise<void>;
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

export class DrizzleApiKeyRepository implements ApiKeyRepository {
  constructor(private db: ShellWatchDB) {}

  async findByHash(hash: string): Promise<ApiKeyInfo | null> {
    const row = this.db
      .select({
        id: apiKeys.id,
        accountId: apiKeys.accountId,
        label: apiKeys.label,
        keyPrefix: apiKeys.keyPrefix,
        scopes: apiKeys.scopes,
        endpoints: apiKeys.endpoints,
        enabled: apiKeys.enabled,
        createdAt: apiKeys.createdAt,
      })
      .from(apiKeys)
      .where(eq(apiKeys.keyHash, hash))
      .get();
    if (!row || !row.enabled) return null;
    return parseRow(row);
  }

  async findAll(): Promise<ApiKeyInfo[]> {
    const rows = this.db
      .select({
        id: apiKeys.id,
        accountId: apiKeys.accountId,
        label: apiKeys.label,
        keyPrefix: apiKeys.keyPrefix,
        scopes: apiKeys.scopes,
        endpoints: apiKeys.endpoints,
        enabled: apiKeys.enabled,
        createdAt: apiKeys.createdAt,
      })
      .from(apiKeys)
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

  async revoke(id: string): Promise<void> {
    this.db.update(apiKeys).set({ enabled: false }).where(eq(apiKeys.id, id)).run();
  }
}

export class InMemoryApiKeyRepository implements ApiKeyRepository {
  private store: (ApiKeyInfo & { keyHash: string })[] = [];

  async findByHash(hash: string): Promise<ApiKeyInfo | null> {
    const key = this.store.find((k) => k.keyHash === hash && k.enabled);
    return key ?? null;
  }

  async findAll(): Promise<ApiKeyInfo[]> {
    return this.store.map(({ keyHash: _, ...rest }) => rest);
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

  async revoke(id: string): Promise<void> {
    const key = this.store.find((k) => k.id === id);
    if (key) key.enabled = false;
  }
}
