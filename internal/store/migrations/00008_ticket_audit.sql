-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- One-time access tickets (#306).
--
-- audit_session_lifecycle: guest sessions are a new session source,
-- 'ticket'. Widening the source CHECK requires a table rebuild (SQLite
-- cannot alter a CHECK in place), as in 00002/00007. The rebuild also adds
-- ticket_id / ticket_label (which ticket admitted the session) and reason:
-- the trigger reason generalized from mcp_reason. MCP rows keep writing
-- mcp_reason for wire compatibility; ticket rows write reason (the guest's
-- self-reported reason for access).
--
-- audit_ticket_events: the ticket event log (minted / redeemed / attached /
-- attempt-failed / retried / admitted / detached / reattached / ended /
-- revoked / expired / invalidated), one row per event, account-scoped like
-- the other audit tables. 'event' carries no CHECK constraint for the same
-- reason notifications.type does not (00003). No ticket token, guest cookie
-- or confirmation-code secret is a credential, so the code is recorded; the
-- token and the cookie never are.
-- +goose Up
CREATE TABLE "audit_session_lifecycle_new" (
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
	"ticket_id" text,
	"ticket_label" text,
	"reason" text,
	FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "audit_session_lifecycle_status_chk" CHECK("status" IN ('open','closed','error')),
	CONSTRAINT "audit_session_lifecycle_source_chk" CHECK("source" IN ('ui','mcp','ssh','ticket'))
);
INSERT INTO "audit_session_lifecycle_new" (
	session_id, account_id, endpoint_id, source, status, created_at, closed_at, duration_ms,
	source_ip, mcp_reason, mcp_client_name, mcp_client_version,
	client_hostname, client_os, client_version, close_reason
) SELECT
	session_id, account_id, endpoint_id, source, status, created_at, closed_at, duration_ms,
	source_ip, mcp_reason, mcp_client_name, mcp_client_version,
	client_hostname, client_os, client_version, close_reason
FROM "audit_session_lifecycle";
DROP TABLE "audit_session_lifecycle";
ALTER TABLE "audit_session_lifecycle_new" RENAME TO "audit_session_lifecycle";
CREATE INDEX "audit_session_lifecycle_account_created_idx" ON "audit_session_lifecycle" ("account_id","created_at","session_id");
CREATE INDEX "audit_session_lifecycle_account_endpoint_created_idx" ON "audit_session_lifecycle" ("account_id","endpoint_id","created_at","session_id");

CREATE TABLE "audit_ticket_events" (
	"id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"ticket_id" text NOT NULL,
	"event" text NOT NULL,
	"created_at" text NOT NULL,
	"endpoint_id" text NOT NULL,
	"ticket_label" text,
	-- redemption channel: 'web' (#306), later 'ssh' (#307).
	"channel" text,
	-- the ticket's options, snapshotted on every row.
	"redeem_ttl_seconds" integer NOT NULL,
	"lifetime_seconds" integer NOT NULL,
	"reason_required" integer NOT NULL,
	"agent_forward" integer NOT NULL,
	-- guest context (self-reported: reason, user_agent).
	"reason" text,
	"source_ip" text,
	"user_agent" text,
	"confirmation_code" text,
	-- the attempt's terminal session and its 1-based number.
	"session_id" text,
	"attempt" integer,
	-- ended / attempt-failed / invalidated: why.
	"end_reason" text,
	"duration_ms" integer,
	FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON UPDATE no action ON DELETE cascade
);
CREATE INDEX "audit_ticket_events_account_created_idx" ON "audit_ticket_events" ("account_id", "created_at" DESC, "id" DESC);
CREATE INDEX "audit_ticket_events_account_ticket_idx" ON "audit_ticket_events" ("account_id", "ticket_id", "created_at" DESC, "id" DESC);

-- +goose Down
-- No-op: migrations are forward-only in this project (matching 00001/00002).
