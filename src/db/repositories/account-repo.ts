import { eq } from "drizzle-orm";
import type { ShellWatchDB } from "../connection.js";
import { accounts, adminAccount } from "../schema.js";

export interface AccountInfo {
  id: string;
  name: string;
  isAdmin: boolean;
  enabled: boolean;
  maxSessions: number;
  agentForward: boolean;
  lastUsedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface AccountRepository {
  findById(id: string): Promise<AccountInfo | null>;
  findAll(): Promise<AccountInfo[]>;
  update(
    id: string,
    data: Partial<Pick<AccountInfo, "name" | "enabled" | "maxSessions" | "agentForward">>,
  ): Promise<void>;
  /** Mark account as active. Writes are batched — call flushLastUsed() to persist. */
  touchLastUsed(id: string): void;
  /** Flush pending lastUsedAt updates to DB. Called periodically, not per-request. */
  flushLastUsed(): void;
  getAdminAccountId(): string | null;
  setAdmin(accountId: string): void;
  isAdmin(accountId: string): boolean;
  destroy(): void;
}

/** No-op implementation for tests that don't need account functionality */
export class StubAccountRepository implements AccountRepository {
  async findById(): Promise<AccountInfo | null> {
    return null;
  }
  async findAll(): Promise<AccountInfo[]> {
    return [];
  }
  async update(): Promise<void> {}
  touchLastUsed(): void {}
  flushLastUsed(): void {}
  destroy(): void {}
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

  async update(
    id: string,
    data: Partial<Pick<AccountInfo, "name" | "enabled" | "maxSessions" | "agentForward">>,
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

  getAdminAccountId(): string | null {
    const row = this.db.select({ accountId: adminAccount.accountId }).from(adminAccount).get();
    return row?.accountId ?? null;
  }

  setAdmin(accountId: string): void {
    // INSERT OR IGNORE — first writer wins. If admin already exists, this is a no-op.
    this.db.insert(adminAccount).values({ singleton: 1, accountId }).onConflictDoNothing().run();
  }

  isAdmin(accountId: string): boolean {
    return this.getAdminAccountId() === accountId;
  }

  /** Flush pending writes and stop the background timer. Call on shutdown. */
  destroy(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    this.flushLastUsed();
  }
}
