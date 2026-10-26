-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- Notification log (#252): server-originated events the user must not miss
-- (first producer: host-key mismatches) are persisted here and pushed over
-- the WebSocket as 'notification:new'. Persistence is the point - a toast on
-- a disconnected tab is lost, a row is not; the client renders the log at
-- /notifications and dedupes toasts by notification id.
-- 'type' carries no CHECK constraint on purpose: widening a CHECK needs a
-- full table rebuild (see 00002), and adding a producer should not need a
-- migration. 'payload' is a JSON object whose shape is typed per 'type'
-- (documented with the Notification schema in docs/api/openapi.yaml).
-- +goose Up
CREATE TABLE "notifications" (
	"id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"type" text NOT NULL,
	"severity" text NOT NULL CHECK ("severity" IN ('info', 'warning', 'error')),
	"title" text NOT NULL,
	"detail" text,
	"payload" text,
	"created_at" text NOT NULL
);
CREATE INDEX "idx_notifications_account_created" ON "notifications" ("account_id", "created_at" DESC, "id" DESC);

-- +goose Down
-- No-op: migrations are forward-only in this project (matching 00001/00002).
