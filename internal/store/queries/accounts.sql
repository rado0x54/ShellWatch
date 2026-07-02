-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- Account queries: the Phase 1 proof of the sqlc pipeline. Ports of
-- src/db/repositories/account-repo.ts arrive surface-by-surface (Phase 2+).
-- Columns are listed explicitly: stable wire shapes, no star expansion.
-- NOTE: keep this file pure ASCII; sqlc's query rewriter computes byte
-- offsets that break on multi-byte characters (mangled SQL output).

-- name: GetAccount :one
SELECT id, name, enabled, max_sessions, last_used_at, created_at, updated_at, show_demo_endpoints
FROM accounts WHERE id = ?;

-- name: ListAccounts :many
SELECT id, name, enabled, max_sessions, last_used_at, created_at, updated_at, show_demo_endpoints
FROM accounts ORDER BY created_at, id;

-- name: TouchAccountLastUsed :exec
UPDATE accounts SET last_used_at = ? WHERE id = ?;

-- name: GetAdminAccountID :one
SELECT account_id FROM admin_account WHERE singleton = 1;
