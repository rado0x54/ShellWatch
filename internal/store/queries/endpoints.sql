-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- Endpoint queries (Phase 3). Every account-owned query takes account_id in
-- SQL (W13). Keep pure ASCII (sqlc offset bug on multi-byte chars).

-- name: ListEndpointsForAccount :many
-- enabled filter matches Node (findAllForAccount, endpoint-repo.ts:87): a
-- soft-deleted endpoint is hidden from lists. Get-by-id deliberately does NOT
-- filter (Node parity: post-delete session create / PUT by id still work).
SELECT id, account_id, label, host, port, username, user_verification, description, agent_forward
FROM endpoints WHERE account_id = ? AND enabled = 1 ORDER BY created_at, id;

-- name: GetEndpointForAccount :one
SELECT id, account_id, label, host, port, username, user_verification, description, agent_forward
FROM endpoints WHERE id = ? AND account_id = ?;

-- name: InsertEndpoint :exec
INSERT INTO endpoints (
  id, account_id, label, host, port, username, user_verification, description,
  agent_forward, enabled, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?);

-- name: DeleteEndpointForAccount :execrows
-- Soft delete (endpoint-repo.ts:146-152): history keeps its endpoint rows and
-- a shared-data-dir cutover can't resurrect Node-era deletions.
UPDATE endpoints SET enabled = 0, updated_at = ? WHERE id = ? AND account_id = ?;

-- name: GetShowDemoEndpoints :one
SELECT show_demo_endpoints FROM accounts WHERE id = ?;

-- name: UpdateEndpoint :execrows
UPDATE endpoints SET label = ?, host = ?, port = ?, username = ?,
  user_verification = ?, description = ?, agent_forward = ?, updated_at = ?
WHERE id = ? AND account_id = ?;
