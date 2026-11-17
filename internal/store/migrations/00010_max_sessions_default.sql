-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- One session limit (#326): max_sessions now counts every active session of
-- the account (UI, MCP and one-time access guests), so its default rises from
-- 5 to 20. Accounts still on the old default move to 20; other values stay.
--
-- SQLite cannot change a column default in place, and accounts is the parent
-- of most tables: the rebuild runs with foreign keys off (which needs to be
-- outside a transaction), so dropping the old table cascades nothing, and
-- the child tables' REFERENCES "accounts" resolve to the new table.
-- +goose NO TRANSACTION
-- +goose Up
PRAGMA foreign_keys = OFF;

-- +goose StatementBegin
BEGIN;
CREATE TABLE "accounts_new" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"enabled" integer DEFAULT true NOT NULL,
	"max_sessions" integer DEFAULT 20 NOT NULL,
	"last_used_at" text,
	"created_at" text NOT NULL,
	"updated_at" text NOT NULL
, "show_demo_endpoints" integer DEFAULT true NOT NULL);
INSERT INTO "accounts_new" ("id", "name", "enabled", "max_sessions", "last_used_at", "created_at", "updated_at", "show_demo_endpoints")
	SELECT "id", "name", "enabled", CASE "max_sessions" WHEN 5 THEN 20 ELSE "max_sessions" END,
		"last_used_at", "created_at", "updated_at", "show_demo_endpoints" FROM "accounts";
DROP TABLE "accounts";
ALTER TABLE "accounts_new" RENAME TO "accounts";
COMMIT;
-- +goose StatementEnd

PRAGMA foreign_keys = ON;

-- +goose Down
-- No-op: migrations are forward-only in this project (matching 00001/00002).
