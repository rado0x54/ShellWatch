import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

// --- Endpoints (replaces config.servers as source of truth) ---

export const endpoints = sqliteTable("endpoints", {
  id: text("id").primaryKey(),
  label: text("label").notNull(),
  host: text("host").notNull(),
  port: integer("port").notNull().default(22),
  username: text("username").notNull(),
  privateKeyPath: text("private_key_path").notNull(),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
});

// --- Session History (records completed sessions) ---

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
