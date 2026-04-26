import { randomUUID } from "node:crypto";
import { and, eq } from "drizzle-orm";
import type { ShellWatchDB } from "../connection.js";
import { pushSubscriptions } from "../schema.js";

export interface PushSubscriptionInfo {
  id: string;
  accountId: string;
  endpoint: string;
  p256dh: string;
  auth: string;
  createdAt: string;
  updatedAt: string;
}

export interface PushSubscriptionRepository {
  findByAccountId(accountId: string): PushSubscriptionInfo[];
  upsert(data: {
    accountId: string;
    endpoint: string;
    p256dh: string;
    auth: string;
  }): PushSubscriptionInfo;
  deleteByEndpointForAccount(accountId: string, endpoint: string): boolean;
}

export class DrizzlePushSubscriptionRepository implements PushSubscriptionRepository {
  constructor(private db: ShellWatchDB) {}

  findByAccountId(accountId: string): PushSubscriptionInfo[] {
    return this.db
      .select()
      .from(pushSubscriptions)
      .where(eq(pushSubscriptions.accountId, accountId))
      .all();
  }

  upsert(data: {
    accountId: string;
    endpoint: string;
    p256dh: string;
    auth: string;
  }): PushSubscriptionInfo {
    const now = new Date().toISOString();
    const id = randomUUID();
    this.db
      .insert(pushSubscriptions)
      .values({ id, ...data, createdAt: now, updatedAt: now })
      .onConflictDoUpdate({
        target: pushSubscriptions.endpoint,
        set: { accountId: data.accountId, p256dh: data.p256dh, auth: data.auth, updatedAt: now },
      })
      .run();

    // Return the row (may be newly inserted or updated)
    const row = this.db
      .select()
      .from(pushSubscriptions)
      .where(eq(pushSubscriptions.endpoint, data.endpoint))
      .get();
    return row!;
  }

  deleteByEndpointForAccount(accountId: string, endpoint: string): boolean {
    const result = this.db
      .delete(pushSubscriptions)
      .where(
        and(eq(pushSubscriptions.accountId, accountId), eq(pushSubscriptions.endpoint, endpoint)),
      )
      .run();
    return result.changes > 0;
  }
}
