import { count, eq } from "drizzle-orm";
import type { ShellWatchDB } from "../connection.js";
import { accounts, adminAccount } from "../schema.js";

export interface AccountInfo {
  id: string;
  name: string;
  type: "human" | "agent";
  isAdmin: boolean;
  enabled: boolean;
  maxSessions: number;
  lastUsedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface AccountRepository {
  findById(id: string): Promise<AccountInfo | null>;
  findAll(): Promise<AccountInfo[]>;
  create(data: { id: string; name: string; type: "human" | "agent" }): Promise<AccountInfo>;
  update(
    id: string,
    data: Partial<Pick<AccountInfo, "name" | "enabled" | "maxSessions">>,
  ): Promise<void>;
  /** Mark account as active. Writes are batched — call flushLastUsed() to persist. */
  touchLastUsed(id: string): void;
  /** Flush pending lastUsedAt updates to DB. Called periodically, not per-request. */
  flushLastUsed(): void;
  count(): number;
  getAdminAccountId(): string | null;
  setAdmin(accountId: string): void;
  isAdmin(accountId: string): boolean;
}

/** No-op implementation for tests that don't need account functionality */
export class StubAccountRepository implements AccountRepository {
  async findById(): Promise<AccountInfo | null> {
    return null;
  }
  async findAll(): Promise<AccountInfo[]> {
    return [];
  }
  async create(data: { id: string; name: string; type: "human" | "agent" }): Promise<AccountInfo> {
    const now = new Date().toISOString();
    return {
      ...data,
      isAdmin: false,
      enabled: true,
      maxSessions: 5,
      lastUsedAt: null,
      createdAt: now,
      updatedAt: now,
    };
  }
  async update(): Promise<void> {}
  touchLastUsed(): void {}
  flushLastUsed(): void {}
  count(): number {
    return 0;
  }
  getAdminAccountId(): string | null {
    return null;
  }
  setAdmin(): void {}
  isAdmin(): boolean {
    return false;
  }
}

const FLUSH_INTERVAL_MS = 60_000; // flush every 60 seconds

export class DrizzleAccountRepository implements AccountRepository {
  private dirtyLastUsed = new Map<string, string>();
  private flushTimer: ReturnType<typeof setInterval> | null = null;

  constructor(private db: ShellWatchDB) {
    this.flushTimer = setInterval(() => this.flushLastUsed(), FLUSH_INTERVAL_MS);
    // Don't keep the process alive just for this timer
    if (this.flushTimer.unref) this.flushTimer.unref();
  }

  async findById(id: string): Promise<AccountInfo | null> {
    const row = this.db.select().from(accounts).where(eq(accounts.id, id)).get();
    if (!row) return null;
    return { ...row, isAdmin: this.isAdmin(id) } as AccountInfo;
  }

  async findAll(): Promise<AccountInfo[]> {
    const rows = this.db.select().from(accounts).all();
    const adminId = this.getAdminAccountId();
    return rows.map((row) => ({
      ...row,
      isAdmin: row.id === adminId,
    })) as AccountInfo[];
  }

  async create(data: { id: string; name: string; type: "human" | "agent" }): Promise<AccountInfo> {
    const now = new Date().toISOString();
    this.db
      .insert(accounts)
      .values({
        ...data,
        enabled: true,
        maxSessions: 5,
        lastUsedAt: now,
        createdAt: now,
        updatedAt: now,
      })
      .run();
    return (await this.findById(data.id))!;
  }

  async update(
    id: string,
    data: Partial<Pick<AccountInfo, "name" | "enabled" | "maxSessions">>,
  ): Promise<void> {
    this.db
      .update(accounts)
      .set({ ...data, updatedAt: new Date().toISOString() })
      .where(eq(accounts.id, id))
      .run();
  }

  touchLastUsed(id: string): void {
    this.dirtyLastUsed.set(id, new Date().toISOString());
  }

  flushLastUsed(): void {
    if (this.dirtyLastUsed.size === 0) return;
    const entries = [...this.dirtyLastUsed.entries()];
    this.dirtyLastUsed.clear();
    for (const [id, timestamp] of entries) {
      this.db.update(accounts).set({ lastUsedAt: timestamp }).where(eq(accounts.id, id)).run();
    }
  }

  count(): number {
    const result = this.db.select({ total: count() }).from(accounts).get();
    return result?.total ?? 0;
  }

  getAdminAccountId(): string | null {
    const row = this.db.select({ accountId: adminAccount.accountId }).from(adminAccount).get();
    return row?.accountId ?? null;
  }

  setAdmin(accountId: string): void {
    this.db.insert(adminAccount).values({ singleton: 1, accountId }).run();
  }

  isAdmin(accountId: string): boolean {
    return this.getAdminAccountId() === accountId;
  }
}
