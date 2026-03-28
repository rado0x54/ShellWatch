import { integer, primaryKey, sqliteTable, text } from "drizzle-orm/sqlite-core";

// --- SSH Keys ---

export const sshKeys = sqliteTable("ssh_keys", {
  id: text("id").primaryKey(),
  label: text("label").notNull(),
  type: text("type").notNull().default("file"), // "file" | "fido" (future)
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

// --- API Keys (placeholder for #15) ---

export const apiKeys = sqliteTable("api_keys", {
  id: text("id").primaryKey(),
  label: text("label").notNull(),
  keyHash: text("key_hash").notNull().unique(),
  keyPrefix: text("key_prefix").notNull(),
  scopes: text("scopes").notNull(),
  endpoints: text("endpoints"),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  createdAt: text("created_at").notNull(),
});
