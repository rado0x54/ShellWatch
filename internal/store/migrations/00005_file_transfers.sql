-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- File-transfer audit log (#263): one row per MCP file operation - inline
-- list/read/write over the session's SFTP channel, and out-of-band link
-- transfers through /api/transfers/{token}. Account-scoped like the other
-- audit tables, surfaced under Audit -> File transfers and on the session
-- detail page.
--
-- Unlike the append-only tables, a link transfer's row is written AHEAD of
-- each state transition (pending -> active -> committing -> terminal) and
-- carries the staging path from the moment staging exists: tokens and live
-- transfers are in-memory only, so after a crash this row is the truthful
-- record. Startup reconciliation turns rows still pending/active/committing
-- into 'failed' (see audit.FileTransfers.ReconcileInterrupted).
--
-- 'status', 'tier' and 'direction' carry no CHECK constraint for the same
-- reason notifications.type does not (00003): widening a CHECK needs a full
-- table rebuild. No transfer token is ever stored here.
-- +goose Up
CREATE TABLE "file_transfers" (
	"id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"session_id" text NOT NULL,
	"endpoint_id" text NOT NULL,
	-- tier: 'inline' | 'link'. direction: 'upload' | 'download' | 'list'.
	"tier" text NOT NULL,
	"direction" text NOT NULL,
	"path" text NOT NULL,
	-- pending | active | committing | completed | failed | cancelled | expired
	"status" text NOT NULL,
	"bytes" integer DEFAULT 0 NOT NULL,
	"total_bytes" integer,
	"sha256" text,
	"error" text,
	-- download only: growth observed by the post-copy extra-byte probe.
	"truncated" integer,
	-- link uploads: 'ok' | 'failed' | 'unknown'.
	"commit_outcome" text,
	-- staging cleanup: 'ok' | 'failed' (staging_path names the leftover).
	"cleanup" text,
	"staging_path" text,
	-- client_id is the AUTHENTICATED OAuth client; name/version are
	-- self-reported by the MCP client.
	"client_id" text,
	"mcp_client_name" text,
	"mcp_client_version" text,
	"source_ip" text,
	"created_at" text NOT NULL,
	"updated_at" text NOT NULL,
	"finished_at" text,
	FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON UPDATE no action ON DELETE cascade
);
CREATE INDEX "file_transfers_account_created_idx" ON "file_transfers" ("account_id", "created_at" DESC, "id" DESC);
CREATE INDEX "file_transfers_account_session_idx" ON "file_transfers" ("account_id", "session_id", "created_at" DESC, "id" DESC);

-- +goose Down
DROP INDEX "file_transfers_account_session_idx";
DROP INDEX "file_transfers_account_created_idx";
DROP TABLE "file_transfers";
