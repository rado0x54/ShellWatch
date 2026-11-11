-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- Baseline schema for the Go backend (#210 Phase 1): byte-for-byte dump of
-- the Node backend's schema after all drizzle migrations (0000-0010),
-- captured via sqlite3 .schema. The schema itself is a frozen invariant of
-- the rewrite (docs/go-backend-architecture.md §1); only the migration tool
-- changes (drizzle-kit -> goose). An existing shellwatch.db is adopted by
-- file-copy: the schema is identical, goose just stamps its version table.
-- +goose Up
CREATE TABLE "accounts" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"enabled" integer DEFAULT true NOT NULL,
	"max_sessions" integer DEFAULT 5 NOT NULL,
	"last_used_at" text,
	"created_at" text NOT NULL,
	"updated_at" text NOT NULL
, "show_demo_endpoints" integer DEFAULT true NOT NULL);
CREATE TABLE "admin_account" (
	"singleton" integer PRIMARY KEY DEFAULT 1 NOT NULL,
	"account_id" text NOT NULL,
	FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON UPDATE no action ON DELETE no action,
	CONSTRAINT "single_row" CHECK("admin_account"."singleton" = 1)
);
CREATE TABLE "endpoints" (
	"id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"label" text NOT NULL,
	"host" text NOT NULL,
	"port" integer DEFAULT 22 NOT NULL,
	"username" text NOT NULL,
	"enabled" integer DEFAULT true NOT NULL,
	"created_at" text NOT NULL,
	"updated_at" text NOT NULL, "user_verification" text DEFAULT 'required' NOT NULL, "description" text, "agent_forward" integer DEFAULT true NOT NULL,
	FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON UPDATE no action ON DELETE no action
);
CREATE TABLE "push_subscriptions" (
	"id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"endpoint" text NOT NULL,
	"p256dh" text NOT NULL,
	"auth" text NOT NULL,
	"created_at" text NOT NULL,
	"updated_at" text NOT NULL,
	FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON UPDATE no action ON DELETE cascade
);
CREATE TABLE "audit_session_lifecycle" (
	"session_id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"endpoint_id" text NOT NULL,
	"source" text NOT NULL,
	"status" text NOT NULL,
	"created_at" text NOT NULL,
	"closed_at" text,
	"duration_ms" integer,
	"source_ip" text,
	"mcp_reason" text,
	"mcp_client_name" text,
	"mcp_client_version" text,
	"client_hostname" text,
	"client_os" text,
	"client_version" text,
	"close_reason" text,
	FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "audit_session_lifecycle_status_chk" CHECK("status" IN ('open','closed','error')),
	CONSTRAINT "audit_session_lifecycle_source_chk" CHECK("source" IN ('ui','mcp','ssh'))
);
CREATE TABLE "ssh_keys" (
	"id" text PRIMARY KEY NOT NULL,
	"label" text NOT NULL,
	"type" text DEFAULT 'file' NOT NULL,
	"public_key" text NOT NULL,
	"fingerprint" text NOT NULL,
	"enabled" integer DEFAULT true NOT NULL,
	"last_used_at" text,
	"created_at" text NOT NULL,
	"updated_at" text NOT NULL
);
CREATE TABLE "webauthn_credentials" (
	"id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"credential_id" text NOT NULL,
	"public_key" blob NOT NULL,
	"counter" integer DEFAULT 0 NOT NULL,
	"transports" text,
	"label" text NOT NULL,
	"public_key_openssh" text,
	"revoked" integer DEFAULT false NOT NULL,
	"created_at" text NOT NULL,
	"last_used_at" text, "state" text DEFAULT 'active' NOT NULL,
	FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON UPDATE no action ON DELETE no action
);
CREATE TABLE "audit_signing_requests" (
	"id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"type" text NOT NULL,
	"source" text NOT NULL,
	"created_at" text NOT NULL,
	"resolved_at" text,
	"outcome" text,
	"latency_ms" integer,
	"source_ip" text,
	"endpoint_label" text,
	"endpoint_address" text,
	"session_id" text,
	"mcp_reason" text,
	"mcp_client_name" text,
	"mcp_client_version" text,
	"client_hostname" text,
	"client_os" text,
	"client_version" text,
	"credential_id" text,
	"passkey_label" text,
	"user_verification" text,
	"key_label" text,
	"key_fingerprint" text,
	"cancel_reason" text,
	FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "audit_signing_requests_type_chk" CHECK("audit_signing_requests"."type" IN ('webauthn-sign','key-approve')),
	CONSTRAINT "audit_signing_requests_source_chk" CHECK("audit_signing_requests"."source" IN ('endpoint-auth','agent-forwarding','agent-proxy')),
	CONSTRAINT "audit_signing_requests_outcome_chk" CHECK("audit_signing_requests"."outcome" IS NULL OR "audit_signing_requests"."outcome" IN ('approved','denied','expired','cancelled'))
);
CREATE UNIQUE INDEX "push_subscriptions_endpoint_unique" ON "push_subscriptions" ("endpoint");
CREATE UNIQUE INDEX "ssh_keys_fingerprint_unique" ON "ssh_keys" ("fingerprint");
CREATE UNIQUE INDEX "webauthn_credentials_credential_id_unique" ON "webauthn_credentials" ("credential_id");
CREATE INDEX "audit_session_lifecycle_account_created_idx" ON "audit_session_lifecycle" ("account_id","created_at","session_id");
CREATE INDEX "audit_session_lifecycle_account_endpoint_created_idx" ON "audit_session_lifecycle" ("account_id","endpoint_id","created_at","session_id");
CREATE INDEX "audit_signing_requests_account_created_idx" ON "audit_signing_requests" ("account_id","created_at","id");

-- +goose Down
-- Baseline: no down migration (never roll back past the initial schema).
