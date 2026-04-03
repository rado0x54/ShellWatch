import { eq } from "drizzle-orm";
import type { ShellWatchDB } from "../connection.js";
import { sshKeys } from "../schema.js";

export interface SshKeyInfo {
  id: string;
  label: string;
  type: string;
  publicKey: string;
  fingerprint: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface SshKeyRepository {
  findAll(): Promise<SshKeyInfo[]>;
  findById(id: string): Promise<SshKeyInfo | null>;
  create(data: {
    id: string;
    label: string;
    type?: string;
    publicKey: string;
    fingerprint: string;
  }): Promise<void>;
  delete(id: string): Promise<void>;
}

export class DrizzleSshKeyRepository implements SshKeyRepository {
  constructor(private db: ShellWatchDB) {}

  async findAll(): Promise<SshKeyInfo[]> {
    return this.db
      .select({
        id: sshKeys.id,
        label: sshKeys.label,
        type: sshKeys.type,
        publicKey: sshKeys.publicKey,
        fingerprint: sshKeys.fingerprint,
        enabled: sshKeys.enabled,
        createdAt: sshKeys.createdAt,
        updatedAt: sshKeys.updatedAt,
      })
      .from(sshKeys)
      .all();
  }

  async findById(id: string): Promise<SshKeyInfo | null> {
    const row = this.db
      .select({
        id: sshKeys.id,
        label: sshKeys.label,
        type: sshKeys.type,
        publicKey: sshKeys.publicKey,
        fingerprint: sshKeys.fingerprint,
        enabled: sshKeys.enabled,
        createdAt: sshKeys.createdAt,
        updatedAt: sshKeys.updatedAt,
      })
      .from(sshKeys)
      .where(eq(sshKeys.id, id))
      .get();
    return row ?? null;
  }

  async create(data: {
    id: string;
    label: string;
    type?: string;
    publicKey: string;
    fingerprint: string;
  }): Promise<void> {
    const now = new Date().toISOString();
    this.db
      .insert(sshKeys)
      .values({
        id: data.id,
        label: data.label,
        type: data.type ?? "file",
        publicKey: data.publicKey,
        fingerprint: data.fingerprint,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      })
      .run();
  }

  async delete(id: string): Promise<void> {
    this.db
      .update(sshKeys)
      .set({ enabled: false, updatedAt: new Date().toISOString() })
      .where(eq(sshKeys.id, id))
      .run();
  }
}

export class InMemorySshKeyRepository implements SshKeyRepository {
  private store: SshKeyInfo[];

  constructor(
    initialKeys: Array<
      Omit<SshKeyInfo, "enabled" | "createdAt" | "updatedAt"> & {
        enabled?: boolean;
        createdAt?: string;
        updatedAt?: string;
      }
    > = [],
  ) {
    const now = new Date().toISOString();
    this.store = initialKeys.map((k) => ({
      ...k,
      enabled: k.enabled ?? true,
      createdAt: k.createdAt ?? now,
      updatedAt: k.updatedAt ?? k.createdAt ?? now,
    }));
  }

  async findAll(): Promise<SshKeyInfo[]> {
    return [...this.store];
  }

  async findById(id: string): Promise<SshKeyInfo | null> {
    return this.store.find((k) => k.id === id) ?? null;
  }

  async create(data: {
    id: string;
    label: string;
    type?: string;
    publicKey: string;
    fingerprint: string;
  }): Promise<void> {
    const now = new Date().toISOString();
    this.store.push({
      id: data.id,
      label: data.label,
      type: data.type ?? "file",
      publicKey: data.publicKey,
      fingerprint: data.fingerprint,
      enabled: true,
      createdAt: now,
      updatedAt: now,
    });
  }

  async delete(id: string): Promise<void> {
    this.store = this.store.filter((k) => k.id !== id);
  }
}
