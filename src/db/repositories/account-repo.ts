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
  touchLastUsed(id: string): void;
  count(): number;
  getAdminAccountId(): string | null;
  setAdmin(accountId: string): void;
  isAdmin(accountId: string): boolean;
}

export class DrizzleAccountRepository implements AccountRepository {
  constructor(private db: ShellWatchDB) {}

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
    this.db
      .update(accounts)
      .set({ lastUsedAt: new Date().toISOString() })
      .where(eq(accounts.id, id))
      .run();
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
