// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { sql } from "drizzle-orm";
import { blob, check, index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

// --- Accounts ---

export const accounts = sqliteTable("accounts", {
  id: text("id").primaryKey(), // UUIDv4
  name: text("name").notNull(),

  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  maxSessions: integer("max_sessions").notNull().default(5),
  // Whether the operator-configured demoEndpoints are merged into this
  // account's endpoint list. Default true; user can hide them from the
  // Endpoints page. Demo endpoints are never copied into the `endpoints`
  // table — config is the source of truth. See src/demo-endpoints/.
  showDemoEndpoints: integer("show_demo_endpoints", { mode: "boolean" }).notNull().default(true),
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
   * Whether to enable SSH agent forwarding when opening a session to this
   * endpoint. Defaults to enabled — some hosts disallow forwarding (e.g.
   * AllowAgentForwarding no in sshd_config) and the user can disable it
   * per-endpoint to avoid a forwarding-channel-rejected handshake.
   */
  agentForward: integer("agent_forward", { mode: "boolean" }).notNull().default(true),
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
//
// Coverage gap: only sessions that successfully reach the `open` state are
// recorded — failed connection attempts (transportFactory throws in
// TerminalManager.create) do not produce audit rows. This is intentional for
// now because the writer's open/close model assumes a session row already
// exists when close fires; capturing failed creates needs a third path that
// synthesizes a directly-errored row. Tracked as a follow-up to #184.

export const auditSessionLifecycle = sqliteTable(
  "audit_session_lifecycle",
  {
    sessionId: text("session_id").primaryKey(),
    accountId: text("account_id")
      .notNull()
      .references(() => accounts.id, { onDelete: "cascade" }),
    // Intentionally no FK to endpoints(id): audit rows must outlive endpoint
    // deletion so post-mortem queries about a removed endpoint still return
    // history. Stored as the original endpoint id; resolution to a label is
    // best-effort at read time.
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
  (table) => [
    // Unfiltered keyset-paged tail: WHERE account_id = ? ORDER BY created_at DESC, session_id DESC.
    // ASC index is fine — SQLite scans it in reverse for the DESC order-by.
    index("audit_session_lifecycle_account_created_idx").on(
      table.accountId,
      table.createdAt,
      table.sessionId,
    ),
    // Endpoint-filtered keyset-paged tail: adds endpoint_id as a leading equality
    // so the same scan strategy applies when ?endpointId is passed.
    index("audit_session_lifecycle_account_endpoint_created_idx").on(
      table.accountId,
      table.endpointId,
      table.createdAt,
      table.sessionId,
    ),
    // Reject typos in the writer at the DB layer rather than corrupting the audit.
    check("audit_session_lifecycle_status_chk", sql`${table.status} IN ('open','closed','error')`),
    check("audit_session_lifecycle_source_chk", sql`${table.source} IN ('ui','mcp','ssh')`),
  ],
);

// --- Signing Request Audit (#186) ---
// Persists every signing request that flows through the broker — passkey
// ceremonies (`webauthn-sign`) and file-key approvals (`key-approve`) — together
// with the outcome (approved / denied / expired / cancelled). Sources: session
// creation (endpoint-auth), agent forwarding (agent-forwarding), /agent-proxy.
//
// Challenge / signature bytes are intentionally NOT stored — high volume, low
// value. credentialId is the correlation key for tying back to a passkey.
//
// Snapshot semantics: descriptive columns (passkey_label, key_label,
// endpoint_label, mcp_client_name, api_key_label, etc.) are recorded as they
// were at sign time and are intentionally not joined back to live tables on
// read. A passkey rename or endpoint relabel must NOT rewrite history; resist
// the urge to "fix" stale-looking values by joining to webauthn_credentials /
// endpoints / api_keys at query time.

export const auditSigningRequests = sqliteTable(
  "audit_signing_requests",
  {
    id: text("id").primaryKey(), // PendingAction.id (22-char base64url)
    accountId: text("account_id")
      .notNull()
      .references(() => accounts.id, { onDelete: "cascade" }),
    type: text("type").notNull(), // 'webauthn-sign' | 'key-approve'
    source: text("source").notNull(), // 'endpoint-auth' | 'agent-forwarding' | 'agent-proxy'
    createdAt: text("created_at").notNull(),
    resolvedAt: text("resolved_at"),
    outcome: text("outcome"), // 'approved' | 'denied' | 'expired' | 'cancelled'
    latencyMs: integer("latency_ms"),
    // Trigger metadata (always-recorded when present)
    sourceIp: text("source_ip"),
    // endpoint-auth + agent-forwarding metadata
    endpointLabel: text("endpoint_label"),
    endpointAddress: text("endpoint_address"),
    // agent-forwarding only — correlates to audit_session_lifecycle (#184)
    sessionId: text("session_id"),
    // endpoint-auth (mcp trigger) metadata
    mcpReason: text("mcp_reason"),
    mcpClientName: text("mcp_client_name"),
    mcpClientVersion: text("mcp_client_version"),
    // agent-proxy + endpoint-auth (mcp) — API-key auth metadata
    apiKeyLabel: text("api_key_label"),
    apiKeyPrefix: text("api_key_prefix"),
    // agent-proxy advertised client metadata
    clientHostname: text("client_hostname"),
    clientOs: text("client_os"),
    clientVersion: text("client_version"),
    // webauthn-sign metadata
    credentialId: text("credential_id"),
    passkeyLabel: text("passkey_label"),
    userVerification: text("user_verification"),
    // key-approve metadata
    keyLabel: text("key_label"),
    keyFingerprint: text("key_fingerprint"),
    // cancelled outcome — reason passed to cancelForConnection()
    cancelReason: text("cancel_reason"),
  },
  (table) => [
    // Keyset-paged tail: WHERE account_id = ? [AND source = ?] [AND outcome = ?]
    // [AND created_at BETWEEN …] ORDER BY created_at DESC, id DESC.
    // Source and outcome have low cardinality, so the planner filters them in
    // a scan over this index rather than needing dedicated indexes.
    index("audit_signing_requests_account_created_idx").on(
      table.accountId,
      table.createdAt,
      table.id,
    ),
    check("audit_signing_requests_type_chk", sql`${table.type} IN ('webauthn-sign','key-approve')`),
    check(
      "audit_signing_requests_source_chk",
      sql`${table.source} IN ('endpoint-auth','agent-forwarding','agent-proxy')`,
    ),
    check(
      "audit_signing_requests_outcome_chk",
      sql`${table.outcome} IS NULL OR ${table.outcome} IN ('approved','denied','expired','cancelled')`,
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

// --- OAuth (#217) ---
// No OAuth-related tables. Ory Hydra is the single store for OAuth clients and
// tokens; ShellWatch keeps no server-side session and no local client index.
// Every token carries the account in its `sub` (the human who logged in), so
// there is nothing to map or persist locally — the bearer gate reads `sub` from
// introspection. The legacy `api_keys` table is dropped (migration 0009).
