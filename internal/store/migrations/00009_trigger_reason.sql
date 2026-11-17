-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- Generic trigger reason (#319).
--
-- The reason a session or sign request was raised is self-reported by an
-- MCP agent or, since #306, by a one-time access guest. It was stored as
-- mcp_reason although it is not MCP-specific; which kind of trigger supplied
-- it is already given by the row (source / type). One generic column now:
--
-- audit_session_lifecycle: 00008 added reason for ticket guests next to
-- mcp_reason; MCP rows move their reason over and mcp_reason is dropped.
-- audit_signing_requests: mcp_reason (already generic) is renamed.
-- notifications: stored session-connect-failed payloads rename the
-- mcpReason key to reason, matching the payload the server now emits.
--
-- No CHECK constraint changes, so no table rebuild is needed (SQLite
-- supports RENAME COLUMN and DROP COLUMN on unindexed columns).
-- +goose Up
UPDATE "audit_session_lifecycle" SET "reason" = "mcp_reason"
	WHERE "reason" IS NULL AND "mcp_reason" IS NOT NULL;
ALTER TABLE audit_session_lifecycle DROP COLUMN mcp_reason;

ALTER TABLE audit_signing_requests RENAME COLUMN mcp_reason TO reason;

UPDATE "notifications"
	SET "payload" = json_remove(json_set("payload", '$.reason', json_extract("payload", '$.mcpReason')), '$.mcpReason')
	WHERE "type" = 'session-connect-failed' AND json_valid("payload")
		AND json_type("payload", '$.mcpReason') IS NOT NULL;

-- +goose Down
-- No-op: migrations are forward-only in this project (matching 00001/00002).
