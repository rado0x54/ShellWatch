import { count, eq } from "drizzle-orm";
import type { ShellWatchDB } from "../connection.js";
import { accounts } from "../schema.js";

export interface AccountInfo {
  id: string;
  name: string;
  type: "human" | "agent";
  role: "admin" | "user";
  enabled: boolean;
  maxSessions: number;
  lastUsedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface AccountRepository {
  findById(id: string): Promise<AccountInfo | null>;
  findAll(): Promise<AccountInfo[]>;
  create(data: {
    id: string;
    name: string;
    type: "human" | "agent";
    role: "admin" | "user";
  }): Promise<AccountInfo>;
  update(
    id: string,
    data: Partial<Pick<AccountInfo, "name" | "enabled" | "maxSessions" | "role">>,
  ): Promise<void>;
  touchLastUsed(id: string): void;
  count(): number;
}

export class DrizzleAccountRepository implements AccountRepository {
  constructor(private db: ShellWatchDB) {}

  async findById(id: string): Promise<AccountInfo | null> {
    const row = this.db.select().from(accounts).where(eq(accounts.id, id)).get();
    return (row as AccountInfo) ?? null;
  }

  async findAll(): Promise<AccountInfo[]> {
    return this.db.select().from(accounts).all() as AccountInfo[];
  }

  async create(data: {
    id: string;
    name: string;
    type: "human" | "agent";
    role: "admin" | "user";
  }): Promise<AccountInfo> {
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
    data: Partial<Pick<AccountInfo, "name" | "enabled" | "maxSessions" | "role">>,
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
}
