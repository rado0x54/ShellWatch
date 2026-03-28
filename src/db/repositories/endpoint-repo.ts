import { eq } from "drizzle-orm";
import type { Endpoint } from "../../config/index.js";
import type { ShellWatchDB } from "../connection.js";
import { endpoints } from "../schema.js";

export interface EndpointRepository {
  findAll(): Promise<Endpoint[]>;
  findById(id: string): Promise<Endpoint | null>;
  create(endpoint: Endpoint): Promise<void>;
  update(id: string, data: Partial<Omit<Endpoint, "id">>): Promise<void>;
  delete(id: string): Promise<void>;
}

/**
 * Drizzle-backed endpoint repository (SQLite).
 */
export class DrizzleEndpointRepository implements EndpointRepository {
  constructor(private db: ShellWatchDB) {}

  async findAll(): Promise<Endpoint[]> {
    const rows = this.db.select().from(endpoints).where(eq(endpoints.enabled, true)).all();
    return rows.map(toEndpoint);
  }

  async findById(id: string): Promise<Endpoint | null> {
    const row = this.db.select().from(endpoints).where(eq(endpoints.id, id)).get();
    if (!row?.enabled) return null;
    return toEndpoint(row);
  }

  async create(endpoint: Endpoint): Promise<void> {
    const now = new Date().toISOString();
    this.db
      .insert(endpoints)
      .values({
        id: endpoint.id,
        label: endpoint.label,
        host: endpoint.host,
        port: endpoint.port,
        username: endpoint.username,
        privateKeyPath: endpoint.privateKeyPath,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      })
      .run();
  }

  async update(id: string, data: Partial<Omit<Endpoint, "id">>): Promise<void> {
    this.db
      .update(endpoints)
      .set({ ...data, updatedAt: new Date().toISOString() })
      .where(eq(endpoints.id, id))
      .run();
  }

  async delete(id: string): Promise<void> {
    this.db
      .update(endpoints)
      .set({ enabled: false, updatedAt: new Date().toISOString() })
      .where(eq(endpoints.id, id))
      .run();
  }
}

/**
 * In-memory endpoint repository — used in tests and as fallback when no DB is configured.
 */
export class InMemoryEndpointRepository implements EndpointRepository {
  private store: Endpoint[];

  constructor(initialEndpoints: Endpoint[] = []) {
    this.store = [...initialEndpoints];
  }

  async findAll(): Promise<Endpoint[]> {
    return [...this.store];
  }

  async findById(id: string): Promise<Endpoint | null> {
    return this.store.find((e) => e.id === id) ?? null;
  }

  async create(endpoint: Endpoint): Promise<void> {
    this.store.push(endpoint);
  }

  async update(id: string, data: Partial<Omit<Endpoint, "id">>): Promise<void> {
    const idx = this.store.findIndex((e) => e.id === id);
    if (idx >= 0) {
      this.store[idx] = { ...this.store[idx], ...data };
    }
  }

  async delete(id: string): Promise<void> {
    this.store = this.store.filter((e) => e.id !== id);
  }
}

function toEndpoint(row: typeof endpoints.$inferSelect): Endpoint {
  return {
    id: row.id,
    label: row.label,
    host: row.host,
    port: row.port,
    username: row.username,
    privateKeyPath: row.privateKeyPath,
  };
}
