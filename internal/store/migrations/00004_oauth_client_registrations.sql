-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- OAuth client registration log (#242): an append-only record of how every
-- MCP/agent client came to exist in Hydra — mediated DCR
-- (POST /api/hydra/register) and CIMD document resolution
-- (GET /api/hydra/authorize) — surfaced to admins under
-- Audit -> OAuth clients.
--
-- DELIBERATELY NOT ACCOUNT-SCOPED, and the only audit table that is not.
-- Both DCR and CIMD run entirely BEFORE any account is identified: there is no
-- subject, no bearer token, only a peer address and a client_id. The other
-- audit tables are 'account_id text NOT NULL' with an FK to accounts(id), so a
-- registration event has no row it could legally occupy there. Reads are
-- admin-only (Store.IsAdmin -> 403), never account-filtered.
--
-- It is a LOG, not a registry: current client state stays in Hydra, which
-- already serves client_id, client_name, scope, redirect_uris, created_at and
-- the metadata.shellwatch.origin marker ShellWatch writes. Nothing here is
-- kept in sync with Hydra, so a client deleted there leaves its history
-- intact — an audit record is supposed to outlive its subject. 'client_id' is
-- therefore an indexed column, not a primary key, and carries no foreign key.
--
-- 'origin' and 'event' carry no CHECK constraint on purpose, for the same
-- reason notifications.type does not (00003): widening a CHECK needs a full
-- table rebuild (see 00002), and #255 already adds a 'blocked' event.
-- Columns are a snapshot denormalized at write time, so history never
-- rewrites when a document changes.

-- +goose Up
CREATE TABLE "oauth_client_registrations" (
	"id" text PRIMARY KEY NOT NULL,
	"client_id" text NOT NULL,
	"origin" text NOT NULL,
	"event" text NOT NULL,
	"client_name" text,
	-- metadata_host is the CIMD Client Identifier URL's hostname: the identity
	-- cue draft-ietf-oauth-client-id-metadata-document-02 §9.1 wants surfaced,
	-- and the one field worth grouping by. NULL for DCR.
	"metadata_host" text,
	"auth_method" text,
	"redirect_uris" text,
	"scope" text,
	-- reason carries the rejection cause for event='rejected'.
	"reason" text,
	"source_ip" text,
	"created_at" text NOT NULL
);

-- Keyset pagination over the whole log (admin view, newest first).
CREATE INDEX "oauth_client_registrations_created_idx"
	ON "oauth_client_registrations" ("created_at" DESC, "id" DESC);

-- "show me everything this client_id ever did".
CREATE INDEX "oauth_client_registrations_client_idx"
	ON "oauth_client_registrations" ("client_id", "created_at" DESC);

-- +goose Down
DROP INDEX "oauth_client_registrations_client_idx";
DROP INDEX "oauth_client_registrations_created_idx";
DROP TABLE "oauth_client_registrations";
