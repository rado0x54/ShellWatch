-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- Host-key pinning (#241): endpoints remember the SSH host key the human
-- approved (or the operator provisioned), and the signing-request audit log
-- gains host-key columns plus two new event types — 'host-key-mismatch'
-- (a connection aborted because the presented key differed from the pin) and
-- 'host-key-cleared' (a pin removed because host/port changed or a human
-- forgot it). Widening the type/source CHECK constraints requires a table
-- rebuild (SQLite cannot alter a CHECK in place).
-- +goose Up
-- Unquoted identifiers: sqlc's SQLite parser rejects quoted names in
-- ALTER TABLE ADD COLUMN (goose/SQLite accept both forms).
ALTER TABLE endpoints ADD COLUMN host_key_type text;
ALTER TABLE endpoints ADD COLUMN host_key blob;
ALTER TABLE endpoints ADD COLUMN host_key_fingerprint text;
ALTER TABLE endpoints ADD COLUMN host_key_pinned_at text;
ALTER TABLE endpoints ADD COLUMN host_key_pinned_by text;

CREATE TABLE "audit_signing_requests_new" (
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
	"endpoint_id" text,
	"host_key_fingerprint" text,
	"host_key_prior_fingerprint" text,
	"host_key_pinned" integer,
	FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "audit_signing_requests_type_chk" CHECK("type" IN ('webauthn-sign','key-approve','host-key-mismatch','host-key-cleared')),
	CONSTRAINT "audit_signing_requests_source_chk" CHECK("source" IN ('endpoint-auth','agent-forwarding','agent-proxy','endpoint-admin')),
	CONSTRAINT "audit_signing_requests_outcome_chk" CHECK("outcome" IS NULL OR "outcome" IN ('approved','denied','expired','cancelled'))
);
INSERT INTO "audit_signing_requests_new" (
	id, account_id, type, source, created_at, resolved_at, outcome, latency_ms,
	source_ip, endpoint_label, endpoint_address, session_id,
	mcp_reason, mcp_client_name, mcp_client_version,
	client_hostname, client_os, client_version,
	credential_id, passkey_label, user_verification, key_label, key_fingerprint, cancel_reason
) SELECT
	id, account_id, type, source, created_at, resolved_at, outcome, latency_ms,
	source_ip, endpoint_label, endpoint_address, session_id,
	mcp_reason, mcp_client_name, mcp_client_version,
	client_hostname, client_os, client_version,
	credential_id, passkey_label, user_verification, key_label, key_fingerprint, cancel_reason
FROM "audit_signing_requests";
DROP TABLE "audit_signing_requests";
ALTER TABLE "audit_signing_requests_new" RENAME TO "audit_signing_requests";
CREATE INDEX "audit_signing_requests_account_created_idx" ON "audit_signing_requests" ("account_id","created_at","id");

-- +goose Down
-- No down migration (the baseline's "never roll back" stance applies: a pin
-- or an audit row, once written, is not silently discarded by a rollback).
