import { eq } from "drizzle-orm";
import type { ShellWatchDB } from "../connection.js";
import { sshKeys } from "../schema.js";

export interface SshKeyInfo {
  id: string;
  label: string;
  type: string;
  privateKeyPath: string | null;
  publicKey: string | null;
}

export interface SshKeyRepository {
  findAll(): Promise<SshKeyInfo[]>;
  findById(id: string): Promise<SshKeyInfo | null>;
  create(data: { id: string; label: string; privateKeyPath: string }): Promise<void>;
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
        privateKeyPath: sshKeys.privateKeyPath,
        publicKey: sshKeys.publicKey,
      })
      .from(sshKeys)
      .where(eq(sshKeys.enabled, true))
      .all();
  }

  async findById(id: string): Promise<SshKeyInfo | null> {
    const row = this.db
      .select({
        id: sshKeys.id,
        label: sshKeys.label,
        type: sshKeys.type,
        privateKeyPath: sshKeys.privateKeyPath,
        publicKey: sshKeys.publicKey,
      })
      .from(sshKeys)
      .where(eq(sshKeys.id, id))
      .get();
    return row ?? null;
  }

  async create(data: { id: string; label: string; privateKeyPath: string }): Promise<void> {
    const now = new Date().toISOString();
    this.db
      .insert(sshKeys)
      .values({
        id: data.id,
        label: data.label,
        type: "file",
        privateKeyPath: data.privateKeyPath,
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

  constructor(initialKeys: Array<{ id: string; label: string; privateKeyPath: string }> = []) {
    this.store = initialKeys.map((k) => ({
      id: k.id,
      label: k.label,
      type: "file",
      privateKeyPath: k.privateKeyPath,
      publicKey: null,
    }));
  }

  async findAll(): Promise<SshKeyInfo[]> {
    return [...this.store];
  }

  async findById(id: string): Promise<SshKeyInfo | null> {
    return this.store.find((k) => k.id === id) ?? null;
  }

  async create(data: { id: string; label: string; privateKeyPath: string }): Promise<void> {
    this.store.push({ ...data, type: "file", publicKey: null });
  }

  async delete(id: string): Promise<void> {
    this.store = this.store.filter((k) => k.id !== id);
  }
}
