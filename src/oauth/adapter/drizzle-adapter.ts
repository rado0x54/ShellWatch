import { eq } from "drizzle-orm";
import type { SQLiteColumn, SQLiteTable } from "drizzle-orm/sqlite-core";
import type { Adapter, AdapterPayload } from "oidc-provider";
import type { ShellWatchDB } from "../../db/connection.js";
import { panvaModelTables, type PanvaModelName } from "./schema.js";

/**
 * Panva Adapter implementation over Drizzle + SQLite.
 *
 * One class per model instance — panva calls our factory with the model name,
 * we return an adapter bound to the corresponding table. All panva model
 * tables share the same column shape (see {@link panvaModelCols} in
 * `./schema.ts`), so one class handles every model type.
 *
 * Panva semantics we honour:
 *
 *  - `find` does **not** filter expired rows. Panva inspects `payload.exp`
 *    itself and rejects stale records at the application layer. Lazy-expiry
 *    cleanup is not our concern here — the tables stay small; a dedicated
 *    GC job can reap expired rows later if volume demands.
 *  - `consume` sets `payload.consumed` to epoch-seconds on the existing
 *    record. Panva uses this to detect replay of authorization codes and
 *    refresh tokens.
 *  - `revokeByGrantId` deletes all rows in *this* model table whose
 *    `grant_id` matches. Panva iterates every grantable model adapter.
 *  - `upsert` extracts `grantId`, `userCode`, `uid` from the payload into
 *    indexed columns so the find-by-X lookups don't scan the JSON.
 */

/**
 * All panva model tables share the same column layout (see `panvaModelCols`
 * in `./schema.ts`), but Drizzle bakes the literal table name into each
 * table's type, so `typeof oauthSessions` and `typeof oauthAccessTokens`
 * are distinct types despite being structurally identical.
 *
 * This alias erases the name-specific part of the type while preserving the
 * column shape the adapter actually reads.
 */
type PanvaTable = SQLiteTable & {
  id: SQLiteColumn;
  payload: SQLiteColumn;
  grantId: SQLiteColumn;
  userCode: SQLiteColumn;
  uid: SQLiteColumn;
  consumedAt: SQLiteColumn;
  expiresAt: SQLiteColumn;
  createdAt: SQLiteColumn;
};

interface PanvaRow {
  id: string;
  payload: AdapterPayload;
  grantId: string | null;
  userCode: string | null;
  uid: string | null;
  consumedAt: string | null;
  expiresAt: string | null;
  createdAt: string;
}

export class DrizzleOidcAdapter implements Adapter {
  constructor(
    private readonly db: ShellWatchDB,
    private readonly table: PanvaTable,
  ) {}

  async upsert(id: string, payload: AdapterPayload, expiresIn: number): Promise<void> {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + expiresIn * 1000).toISOString();

    // Panva's AdapterPayload is typed loosely; these fields may or may not
    // be present depending on model and state.
    const payloadAny = payload as AdapterPayload & {
      grantId?: string;
      userCode?: string;
      uid?: string;
      consumed?: number;
    };

    const row = {
      id,
      payload,
      grantId: payloadAny.grantId ?? null,
      userCode: payloadAny.userCode ?? null,
      uid: payloadAny.uid ?? null,
      consumedAt: payloadAny.consumed ? new Date(payloadAny.consumed * 1000).toISOString() : null,
      expiresAt,
      createdAt: now.toISOString(),
    };

    await this.db
      .insert(this.table)
      .values(row)
      .onConflictDoUpdate({
        target: this.table.id,
        set: {
          payload: row.payload,
          grantId: row.grantId,
          userCode: row.userCode,
          uid: row.uid,
          consumedAt: row.consumedAt,
          expiresAt: row.expiresAt,
        },
      });
  }

  async find(id: string): Promise<AdapterPayload | undefined> {
    const rows = (await this.db
      .select()
      .from(this.table)
      .where(eq(this.table.id, id))
      .limit(1)) as PanvaRow[];
    return rows[0]?.payload;
  }

  async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    const rows = (await this.db
      .select()
      .from(this.table)
      .where(eq(this.table.userCode, userCode))
      .limit(1)) as PanvaRow[];
    return rows[0]?.payload;
  }

  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    const rows = (await this.db
      .select()
      .from(this.table)
      .where(eq(this.table.uid, uid))
      .limit(1)) as PanvaRow[];
    return rows[0]?.payload;
  }

  async consume(id: string): Promise<void> {
    const rows = (await this.db
      .select()
      .from(this.table)
      .where(eq(this.table.id, id))
      .limit(1)) as PanvaRow[];
    if (!rows[0]) return;

    const consumedEpoch = Math.floor(Date.now() / 1000);
    const updatedPayload: AdapterPayload = {
      ...rows[0].payload,
      consumed: consumedEpoch,
    };

    await this.db
      .update(this.table)
      .set({
        payload: updatedPayload,
        consumedAt: new Date(consumedEpoch * 1000).toISOString(),
      })
      .where(eq(this.table.id, id));
  }

  async destroy(id: string): Promise<void> {
    await this.db.delete(this.table).where(eq(this.table.id, id));
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    await this.db.delete(this.table).where(eq(this.table.grantId, grantId));
  }
}

/**
 * Factory used by panva's Provider config. Panva calls this with a model
 * name (e.g. "AccessToken") and expects an Adapter instance back.
 */
export function createDrizzleAdapterFactory(db: ShellWatchDB): (name: string) => Adapter {
  return (name: string) => {
    const table = panvaModelTables[name as PanvaModelName];
    if (!table) {
      throw new Error(`oauth: unknown panva model "${name}"`);
    }
    return new DrizzleOidcAdapter(db, table as PanvaTable);
  };
}
