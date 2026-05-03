// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { and, eq } from "drizzle-orm";
import type { ShellWatchDB } from "../connection.js";
import { endpoints } from "../schema.js";

export type UserVerification = "required" | "preferred" | "discouraged";

export const USER_VERIFICATION_VALUES: readonly UserVerification[] = [
  "required",
  "preferred",
  "discouraged",
] as const;

export function isUserVerification(value: unknown): value is UserVerification {
  return (
    typeof value === "string" && (USER_VERIFICATION_VALUES as readonly string[]).includes(value)
  );
}

export const ENDPOINT_DESCRIPTION_MAX_LENGTH = 1000;

export interface EndpointInfo {
  id: string;
  accountId: string;
  label: string;
  host: string;
  port: number;
  username: string;
  userVerification: UserVerification;
  description: string | null;
}

// All read methods are account-scoped by design — there are no callers that
// legitimately need to enumerate or look up endpoints across tenants. If a new
// caller needs cross-account access, surface it via a separate admin handle
// rather than reintroducing unscoped reads on this interface (see #136).
export interface EndpointRepository {
  findAllForAccount(accountId: string): Promise<EndpointInfo[]>;
  findByIdForAccount(id: string, accountId: string): Promise<EndpointInfo | null>;
  create(data: {
    id: string;
    accountId: string;
    label: string;
    host: string;
    port: number;
    username: string;
    userVerification?: UserVerification;
    description?: string | null;
  }): Promise<void>;
  update(
    id: string,
    accountId: string,
    data: Partial<{
      label: string;
      host: string;
      port: number;
      username: string;
      userVerification: UserVerification;
      description: string | null;
    }>,
  ): Promise<void>;
  delete(id: string, accountId: string): Promise<void>;
}

const ENDPOINT_COLUMNS = {
  id: endpoints.id,
  accountId: endpoints.accountId,
  label: endpoints.label,
  host: endpoints.host,
  port: endpoints.port,
  username: endpoints.username,
  userVerification: endpoints.userVerification,
  description: endpoints.description,
} as const;

export class DrizzleEndpointRepository implements EndpointRepository {
  constructor(private db: ShellWatchDB) {}

  async findAllForAccount(accountId: string): Promise<EndpointInfo[]> {
    return this.db
      .select(ENDPOINT_COLUMNS)
      .from(endpoints)
      .where(and(eq(endpoints.accountId, accountId), eq(endpoints.enabled, true)))
      .all() as EndpointInfo[];
  }

  async findByIdForAccount(id: string, accountId: string): Promise<EndpointInfo | null> {
    const row = this.db
      .select(ENDPOINT_COLUMNS)
      .from(endpoints)
      .where(and(eq(endpoints.id, id), eq(endpoints.accountId, accountId)))
      .get();
    return (row as EndpointInfo | undefined) ?? null;
  }

  async create(data: {
    id: string;
    accountId: string;
    label: string;
    host: string;
    port: number;
    username: string;
    userVerification?: UserVerification;
    description?: string | null;
  }): Promise<void> {
    const now = new Date().toISOString();
    this.db
      .insert(endpoints)
      .values({
        ...data,
        userVerification: data.userVerification ?? "required",
        description: data.description ?? null,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      })
      .run();
  }

  async update(
    id: string,
    accountId: string,
    data: Partial<{
      label: string;
      host: string;
      port: number;
      username: string;
      userVerification: UserVerification;
      description: string | null;
    }>,
  ): Promise<void> {
    this.db
      .update(endpoints)
      .set({ ...data, updatedAt: new Date().toISOString() })
      .where(and(eq(endpoints.id, id), eq(endpoints.accountId, accountId)))
      .run();
  }

  async delete(id: string, accountId: string): Promise<void> {
    this.db
      .update(endpoints)
      .set({ enabled: false, updatedAt: new Date().toISOString() })
      .where(and(eq(endpoints.id, id), eq(endpoints.accountId, accountId)))
      .run();
  }
}

export class InMemoryEndpointRepository implements EndpointRepository {
  private store: EndpointInfo[];

  constructor(
    initialEndpoints: Array<
      Omit<EndpointInfo, "accountId" | "userVerification" | "description"> & {
        accountId?: string;
        userVerification?: UserVerification;
        description?: string | null;
      }
    > = [],
    private defaultAccountId = "test-account",
  ) {
    this.store = initialEndpoints.map((e) => ({
      ...e,
      accountId: e.accountId ?? this.defaultAccountId,
      userVerification: e.userVerification ?? "required",
      description: e.description ?? null,
    }));
  }

  async findAllForAccount(accountId: string): Promise<EndpointInfo[]> {
    return this.store.filter((e) => e.accountId === accountId);
  }

  async findByIdForAccount(id: string, accountId: string): Promise<EndpointInfo | null> {
    return this.store.find((e) => e.id === id && e.accountId === accountId) ?? null;
  }

  async create(data: {
    id: string;
    accountId: string;
    label: string;
    host: string;
    port: number;
    username: string;
    userVerification?: UserVerification;
    description?: string | null;
  }): Promise<void> {
    this.store.push({
      ...data,
      userVerification: data.userVerification ?? "required",
      description: data.description ?? null,
    });
  }

  async update(
    id: string,
    accountId: string,
    data: Partial<{
      label: string;
      host: string;
      port: number;
      username: string;
      userVerification: UserVerification;
      description: string | null;
    }>,
  ): Promise<void> {
    const idx = this.store.findIndex((e) => e.id === id && e.accountId === accountId);
    if (idx >= 0) this.store[idx] = { ...this.store[idx], ...data };
  }

  async delete(id: string, accountId: string): Promise<void> {
    this.store = this.store.filter((e) => !(e.id === id && e.accountId === accountId));
  }
}
