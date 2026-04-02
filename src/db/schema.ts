import { sql } from "drizzle-orm";
import { blob, check, integer, primaryKey, sqliteTable, text } from "drizzle-orm/sqlite-core";

// --- Accounts ---

export const accounts = sqliteTable("accounts", {
  id: text("id").primaryKey(), // UUIDv4
  name: text("name").notNull(),
  type: text("type").notNull(), // "human" | "agent"
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  maxSessions: integer("max_sessions").notNull().default(5),
  recoveryCodeHash: text("recovery_code_hash"),
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
  accountId: text("account_id").references(() => accounts.id),
  credentialId: text("credential_id").notNull().unique(), // base64url-encoded
  publicKey: blob("public_key", { mode: "buffer" }).notNull(), // COSE-encoded
  counter: integer("counter").notNull().default(0),
  transports: text("transports"), // JSON array: ["usb", "nfc", "ble", "internal"]
  label: text("label").notNull(), // User-friendly name (e.g., "YubiKey 5 NFC")
  publicKeyOpenSsh: text("public_key_openssh"), // OpenSSH authorized_keys format (if convertible)
  createdAt: text("created_at").notNull(),
  lastUsedAt: text("last_used_at"),
});

// --- SSH Keys ---

export const sshKeys = sqliteTable("ssh_keys", {
  id: text("id").primaryKey(),
  label: text("label").notNull(),
  type: text("type").notNull().default("file"), // "file" | "webauthn"
  publicKey: text("public_key").notNull(), // OpenSSH format (e.g., "ssh-ed25519 AAAA...")
  fingerprint: text("fingerprint").notNull().unique(), // SHA256:... — used to match runtime key files
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
});

// --- Endpoints ---

export const endpoints = sqliteTable("endpoints", {
  id: text("id").primaryKey(),
  label: text("label").notNull(),
  host: text("host").notNull(),
  port: integer("port").notNull().default(22),
  username: text("username").notNull(),
  keyId: text("key_id").references(() => sshKeys.id),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
});

// --- Endpoint ↔ Key (many-to-many for future multi-key support) ---

export const endpointKeys = sqliteTable(
  "endpoint_keys",
  {
    endpointId: text("endpoint_id")
      .notNull()
      .references(() => endpoints.id),
    keyId: text("key_id")
      .notNull()
      .references(() => sshKeys.id),
  },
  (table) => [primaryKey({ columns: [table.endpointId, table.keyId] })],
);

// --- Session History ---

export const sessionHistory = sqliteTable("session_history", {
  sessionId: text("session_id").primaryKey(),
  endpointId: text("endpoint_id").notNull(),
  accountId: text("account_id"),
  source: text("source").notNull(),
  status: text("status").notNull(),
  createdAt: text("created_at").notNull(),
  closedAt: text("closed_at"),
  durationMs: integer("duration_ms"),
});

// --- Audit Events (placeholder for #16) ---

export const auditEvents = sqliteTable("audit_events", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  timestamp: text("timestamp").notNull(),
  sessionId: text("session_id"),
  accountId: text("account_id"),
  eventType: text("event_type").notNull(),
  data: text("data"),
});

// --- Guardrail Rules (placeholder for #13) ---

export const guardrailRules = sqliteTable("guardrail_rules", {
  id: text("id").primaryKey(),
  name: text("name").notNull().unique(),
  pattern: text("pattern").notNull(),
  action: text("action").notNull(),
  message: text("message"),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  priority: integer("priority").notNull().default(0),
  endpointId: text("endpoint_id"),
  source: text("source"),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
});

// --- API Keys ---

export const apiKeys = sqliteTable("api_keys", {
  id: text("id").primaryKey(),
  accountId: text("account_id").references(() => accounts.id),
  label: text("label").notNull(),
  keyHash: text("key_hash").notNull().unique(),
  keyPrefix: text("key_prefix").notNull(),
  scopes: text("scopes").notNull(),
  endpoints: text("endpoints"),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  createdAt: text("created_at").notNull(),
});
