import { and, eq } from "drizzle-orm";
import type { ShellWatchDB } from "../connection.js";
import { endpoints } from "../schema.js";

export interface EndpointInfo {
  id: string;
  accountId: string;
  label: string;
  host: string;
  port: number;
  username: string;
}

export interface EndpointRepository {
  /** Scoped — returns only endpoints owned by this account. Use for API/UI. */
  findAllForAccount(accountId: string): Promise<EndpointInfo[]>;
  /** Scoped lookup — verifies ownership. Use for API handlers. */
  findByIdForAccount(id: string, accountId: string): Promise<EndpointInfo | null>;
  /** Unscoped — all enabled endpoints. For internal use (MCP, transport). */
  findAll(): Promise<EndpointInfo[]>;
  /** Unscoped lookup — for internal use (transport, terminal manager). */
  findById(id: string): Promise<EndpointInfo | null>;
  create(data: {
    id: string;
    accountId: string;
    label: string;
    host: string;
    port: number;
    username: string;
  }): Promise<void>;
  update(
    id: string,
    accountId: string,
    data: Partial<{
      label: string;
      host: string;
      port: number;
      username: string;
    }>,
  ): Promise<void>;
  delete(id: string, accountId: string): Promise<void>;
}

const ENDPOINT_COLUMNS = {
  id: endpoints.id,
  accountId: endpoints.accountId,
  label: endpoints.label,
  host: endpoints.host,
  port: endpoints.port,
  username: endpoints.username,
} as const;

export class DrizzleEndpointRepository implements EndpointRepository {
  constructor(private db: ShellWatchDB) {}

  async findAllForAccount(accountId: string): Promise<EndpointInfo[]> {
    return this.db
      .select(ENDPOINT_COLUMNS)
      .from(endpoints)
      .where(and(eq(endpoints.accountId, accountId), eq(endpoints.enabled, true)))
      .all();
  }

  async findAll(): Promise<EndpointInfo[]> {
    return this.db
      .select(ENDPOINT_COLUMNS)
      .from(endpoints)
      .where(eq(endpoints.enabled, true))
      .all();
  }

  async findByIdForAccount(id: string, accountId: string): Promise<EndpointInfo | null> {
    const row = this.db
      .select(ENDPOINT_COLUMNS)
      .from(endpoints)
      .where(and(eq(endpoints.id, id), eq(endpoints.accountId, accountId)))
      .get();
    return row ?? null;
  }

  async findById(id: string): Promise<EndpointInfo | null> {
    const row = this.db.select(ENDPOINT_COLUMNS).from(endpoints).where(eq(endpoints.id, id)).get();
    return row ?? null;
  }

  async create(data: {
    id: string;
    accountId: string;
    label: string;
    host: string;
    port: number;
    username: string;
  }): Promise<void> {
    const now = new Date().toISOString();
    this.db
      .insert(endpoints)
      .values({
        ...data,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      })
      .run();
  }

  async update(
    id: string,
    accountId: string,
    data: Partial<{
      label: string;
      host: string;
      port: number;
      username: string;
    }>,
  ): Promise<void> {
    this.db
      .update(endpoints)
      .set({ ...data, updatedAt: new Date().toISOString() })
      .where(and(eq(endpoints.id, id), eq(endpoints.accountId, accountId)))
      .run();
  }

  async delete(id: string, accountId: string): Promise<void> {
    this.db
      .update(endpoints)
      .set({ enabled: false, updatedAt: new Date().toISOString() })
      .where(and(eq(endpoints.id, id), eq(endpoints.accountId, accountId)))
      .run();
  }
}

export class InMemoryEndpointRepository implements EndpointRepository {
  private store: EndpointInfo[];

  constructor(
    initialEndpoints: Array<Omit<EndpointInfo, "accountId"> & { accountId?: string }> = [],
    private defaultAccountId = "test-account",
  ) {
    this.store = initialEndpoints.map((e) => ({
      ...e,
      accountId: e.accountId ?? this.defaultAccountId,
    }));
  }

  async findAll(): Promise<EndpointInfo[]> {
    return [...this.store];
  }

  async findAllForAccount(accountId: string): Promise<EndpointInfo[]> {
    return this.store.filter((e) => e.accountId === accountId);
  }

  async findByIdForAccount(id: string, accountId: string): Promise<EndpointInfo | null> {
    return this.store.find((e) => e.id === id && e.accountId === accountId) ?? null;
  }

  async findById(id: string): Promise<EndpointInfo | null> {
    return this.store.find((e) => e.id === id) ?? null;
  }

  async create(data: {
    id: string;
    accountId: string;
    label: string;
    host: string;
    port: number;
    username: string;
  }): Promise<void> {
    this.store.push({ ...data });
  }

  async update(
    id: string,
    accountId: string,
    data: Partial<{
      label: string;
      host: string;
      port: number;
      username: string;
    }>,
  ): Promise<void> {
    const idx = this.store.findIndex((e) => e.id === id && e.accountId === accountId);
    if (idx >= 0) this.store[idx] = { ...this.store[idx], ...data };
  }

  async delete(id: string, accountId: string): Promise<void> {
    this.store = this.store.filter((e) => !(e.id === id && e.accountId === accountId));
  }
}
