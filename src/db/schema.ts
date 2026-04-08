import { sql } from "drizzle-orm";
import { blob, check, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

// --- Accounts ---

export const accounts = sqliteTable("accounts", {
  id: text("id").primaryKey(), // UUIDv4
  name: text("name").notNull(),

  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  maxSessions: integer("max_sessions").notNull().default(5),
  agentForward: integer("agent_forward", { mode: "boolean" }).notNull().default(false),
  lastUsedAt: text("last_used_at"),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
});

// --- Admin Account (singleton — at most one row) ---

export const adminAccount = sqliteTable(
  "admin_account",
  {
    singleton: integer("singleton").primaryKey().default(1),
    accountId: text("account_id")
      .notNull()
      .references(() => accounts.id),
  },
  (table) => [check("single_row", sql`${table.singleton} = 1`)],
);

// --- WebAuthn Credentials ---

export const webauthnCredentials = sqliteTable("webauthn_credentials", {
  id: text("id").primaryKey(),
  accountId: text("account_id")
    .notNull()
    .references(() => accounts.id),
  credentialId: text("credential_id").notNull().unique(), // base64url-encoded
  publicKey: blob("public_key", { mode: "buffer" }).notNull(), // COSE-encoded
  counter: integer("counter").notNull().default(0),
  transports: text("transports"), // JSON array: ["usb", "nfc", "ble", "internal"]
  label: text("label").notNull(), // User-friendly name (e.g., "YubiKey 5 NFC")
  publicKeyOpenSsh: text("public_key_openssh"), // OpenSSH authorized_keys format (if convertible)
  revoked: integer("revoked", { mode: "boolean" }).notNull().default(false),
  createdAt: text("created_at").notNull(),
  lastUsedAt: text("last_used_at"),
});

// --- SSH Keys (file-based only — passkeys live in webauthn_credentials) ---

export const sshKeys = sqliteTable("ssh_keys", {
  id: text("id").primaryKey(),
  label: text("label").notNull(),
  type: text("type").notNull().default("file"), // kept for backward compat; always "file" going forward
  publicKey: text("public_key").notNull(), // OpenSSH format (e.g., "ssh-ed25519 AAAA...")
  fingerprint: text("fingerprint").notNull().unique(), // SHA256:... — used to match runtime key files
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  lastUsedAt: text("last_used_at"),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
});

// --- Endpoints ---

export const endpoints = sqliteTable("endpoints", {
  id: text("id").primaryKey(),
  accountId: text("account_id")
    .notNull()
    .references(() => accounts.id),
  label: text("label").notNull(),
  host: text("host").notNull(),
  port: integer("port").notNull().default(22),
  username: text("username").notNull(),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
});

// --- Session History ---

export const sessionHistory = sqliteTable("session_history", {
  sessionId: text("session_id").primaryKey(),
  endpointId: text("endpoint_id").notNull(),
  accountId: text("account_id").notNull(),
  source: text("source").notNull(),
  status: text("status").notNull(),
  createdAt: text("created_at").notNull(),
  closedAt: text("closed_at"),
  durationMs: integer("duration_ms"),
});

// --- API Keys ---

export const apiKeys = sqliteTable("api_keys", {
  id: text("id").primaryKey(),
  accountId: text("account_id")
    .notNull()
    .references(() => accounts.id),
  label: text("label").notNull(),
  keyHash: text("key_hash").notNull().unique(),
  keyPrefix: text("key_prefix").notNull(),
  scopes: text("scopes").notNull(),
  endpoints: text("endpoints"),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  createdAt: text("created_at").notNull(),
});
