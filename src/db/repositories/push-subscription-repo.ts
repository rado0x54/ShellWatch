// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
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

// Every method here takes an accountId and operates only on that account's
// rows. There is no scoped/admin split because there are no cross-tenant
// reads or writes — the dispatcher loops over `findByAccountId(action.accountId)`,
// route handlers use the caller's `request.accountId`, and `upsert` rejects
// any endpoint that already belongs to a different account (see #131). Do
// not add an unscoped variant without revisiting that constraint.
export interface PushSubscriptionRepository {
  findByAccountId(accountId: string): PushSubscriptionInfo[];
  upsert(data: {
    accountId: string;
    endpoint: string;
    p256dh: string;
    auth: string;
  }): PushSubscriptionInfo | null;
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
  }): PushSubscriptionInfo | null {
    // Endpoints are UNIQUE across the table. Treat them as an account-bound
    // resource: a different account claiming the same endpoint must be rejected,
    // otherwise the conflict-do-update would silently transfer ownership.
    const existing = this.db
      .select()
      .from(pushSubscriptions)
      .where(eq(pushSubscriptions.endpoint, data.endpoint))
      .get();
    if (existing && existing.accountId !== data.accountId) {
      return null;
    }

    const now = new Date().toISOString();
    const id = existing?.id ?? randomUUID();
    this.db
      .insert(pushSubscriptions)
      .values({ id, ...data, createdAt: now, updatedAt: now })
      .onConflictDoUpdate({
        target: pushSubscriptions.endpoint,
        set: { p256dh: data.p256dh, auth: data.auth, updatedAt: now },
      })
      .run();

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
