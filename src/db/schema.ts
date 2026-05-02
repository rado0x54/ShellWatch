import { sql } from "drizzle-orm";
import { blob, check, index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

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
  /**
   * Lifecycle state. `active` = usable for login, SSH signing, listed as SSH key.
   * `pending_confirmation` = registered via an invite but not yet confirmed by the
   * inviting (already-authenticated) device. Pending creds are listed in account
   * settings only — never returned to login flows or SSH signing.
   */
  state: text("state").notNull().default("active"),
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
  /**
   * WebAuthn `userVerification` setting used for agent-proxy sign ceremonies
   * to this endpoint. One of "required" | "preferred" | "discouraged".
   * Defaults to "required" — the user can relax it per endpoint if a given
   * host / authenticator can't provide UV.
   */
  userVerification: text("user_verification").notNull().default("required"),
  /**
   * Optional free-form description (max 1000 chars). Surfaced to MCP agents in
   * the per-endpoint instructions so they have context about what runs on the
   * host (e.g., "production DB host, runs Postgres 15, /srv/data holds nightly dumps").
   */
  description: text("description"),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
});

// --- Session Lifecycle Audit (#184) ---
// Tracks session open → close transitions and the metadata available at each
// boundary. Replaces the unused `session_history` table from the original schema.

export const auditSessionLifecycle = sqliteTable(
  "audit_session_lifecycle",
  {
    sessionId: text("session_id").primaryKey(),
    accountId: text("account_id")
      .notNull()
      .references(() => accounts.id, { onDelete: "cascade" }),
    endpointId: text("endpoint_id").notNull(),
    source: text("source").notNull(), // 'ui' | 'mcp' | 'ssh'
    status: text("status").notNull(), // 'open' | 'closed' | 'error'
    createdAt: text("created_at").notNull(),
    closedAt: text("closed_at"),
    durationMs: integer("duration_ms"),
    // Trigger metadata (always-recorded when present)
    sourceIp: text("source_ip"),
    // MCP-trigger-only metadata
    mcpReason: text("mcp_reason"),
    mcpClientName: text("mcp_client_name"),
    mcpClientVersion: text("mcp_client_version"),
    // API-key-auth metadata (set whenever the session was authenticated via an API key)
    apiKeyLabel: text("api_key_label"),
    apiKeyPrefix: text("api_key_prefix"),
    // Agent-client metadata — populated for sessions opened via shellwatch-agent
    // paths once #12 (SSH bastion) lands. Reserved columns; left null until then.
    clientHostname: text("client_hostname"),
    clientOs: text("client_os"),
    clientVersion: text("client_version"),
    // Why the session ended (null while open, set on close transition).
    // Subset of CloseReason (#185); see TerminalManager.
    closeReason: text("close_reason"),
  },
  // Serves the keyset-paged list query: WHERE account_id = ? ORDER BY created_at DESC, session_id DESC.
  // ASC index is fine — SQLite scans it in reverse for the DESC order-by.
  (table) => [
    index("audit_session_lifecycle_account_created_idx").on(
      table.accountId,
      table.createdAt,
      table.sessionId,
    ),
  ],
);

// --- Push Subscriptions (Web Push API) ---

export const pushSubscriptions = sqliteTable("push_subscriptions", {
  id: text("id").primaryKey(), // UUIDv4
  accountId: text("account_id")
    .notNull()
    .references(() => accounts.id, { onDelete: "cascade" }),
  endpoint: text("endpoint").notNull().unique(), // Push service URL (unique per browser)
  p256dh: text("p256dh").notNull(), // Base64url-encoded public key
  auth: text("auth").notNull(), // Base64url-encoded auth secret
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
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
