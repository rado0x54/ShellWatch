import { eq } from "drizzle-orm";
import type { ShellWatchDB } from "../connection.js";
import { endpoints } from "../schema.js";

export interface EndpointInfo {
  id: string;
  label: string;
  host: string;
  port: number;
  username: string;
  keyId: string | null;
}

export interface EndpointRepository {
  findAll(): Promise<EndpointInfo[]>;
  findById(id: string): Promise<EndpointInfo | null>;
  create(data: {
    id: string;
    label: string;
    host: string;
    port: number;
    username: string;
    keyId?: string;
  }): Promise<void>;
  update(
    id: string,
    data: Partial<{ label: string; host: string; port: number; username: string; keyId: string }>,
  ): Promise<void>;
  delete(id: string): Promise<void>;
}

export class DrizzleEndpointRepository implements EndpointRepository {
  constructor(private db: ShellWatchDB) {}

  async findAll(): Promise<EndpointInfo[]> {
    return this.db
      .select({
        id: endpoints.id,
        label: endpoints.label,
        host: endpoints.host,
        port: endpoints.port,
        username: endpoints.username,
        keyId: endpoints.keyId,
      })
      .from(endpoints)
      .where(eq(endpoints.enabled, true))
      .all();
  }

  async findById(id: string): Promise<EndpointInfo | null> {
    const row = this.db
      .select({
        id: endpoints.id,
        label: endpoints.label,
        host: endpoints.host,
        port: endpoints.port,
        username: endpoints.username,
        keyId: endpoints.keyId,
      })
      .from(endpoints)
      .where(eq(endpoints.id, id))
      .get();
    return row ?? null;
  }

  async create(data: {
    id: string;
    label: string;
    host: string;
    port: number;
    username: string;
    keyId?: string;
  }): Promise<void> {
    const now = new Date().toISOString();
    this.db
      .insert(endpoints)
      .values({ ...data, keyId: data.keyId ?? null, enabled: true, createdAt: now, updatedAt: now })
      .run();
  }

  async update(
    id: string,
    data: Partial<{ label: string; host: string; port: number; username: string; keyId: string }>,
  ): Promise<void> {
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

export class InMemoryEndpointRepository implements EndpointRepository {
  private store: EndpointInfo[];

  constructor(initialEndpoints: Array<Omit<EndpointInfo, "keyId"> & { keyId?: string }> = []) {
    this.store = initialEndpoints.map((e) => ({ ...e, keyId: e.keyId ?? null }));
  }

  async findAll(): Promise<EndpointInfo[]> {
    return [...this.store];
  }

  async findById(id: string): Promise<EndpointInfo | null> {
    return this.store.find((e) => e.id === id) ?? null;
  }

  async create(data: {
    id: string;
    label: string;
    host: string;
    port: number;
    username: string;
    keyId?: string;
  }): Promise<void> {
    this.store.push({ ...data, keyId: data.keyId ?? null });
  }

  async update(
    id: string,
    data: Partial<{ label: string; host: string; port: number; username: string; keyId: string }>,
  ): Promise<void> {
    const idx = this.store.findIndex((e) => e.id === id);
    if (idx >= 0) this.store[idx] = { ...this.store[idx], ...data };
  }

  async delete(id: string): Promise<void> {
    this.store = this.store.filter((e) => e.id !== id);
  }
}
