-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- Endpoint queries (Phase 3). Every account-owned query takes account_id in
-- SQL (W13). Keep pure ASCII (sqlc offset bug on multi-byte chars).

-- name: ListEndpointsForAccount :many
SELECT id, account_id, label, host, port, username, user_verification, description, agent_forward
FROM endpoints WHERE account_id = ? ORDER BY created_at, id;

-- name: GetEndpointForAccount :one
SELECT id, account_id, label, host, port, username, user_verification, description, agent_forward
FROM endpoints WHERE id = ? AND account_id = ?;

-- name: InsertEndpoint :exec
INSERT INTO endpoints (
  id, account_id, label, host, port, username, user_verification, description,
  agent_forward, enabled, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?);

-- name: DeleteEndpointForAccount :execrows
DELETE FROM endpoints WHERE id = ? AND account_id = ?;

-- name: GetShowDemoEndpoints :one
SELECT show_demo_endpoints FROM accounts WHERE id = ?;

-- name: UpdateEndpoint :execrows
UPDATE endpoints SET label = ?, host = ?, port = ?, username = ?,
  user_verification = ?, description = ?, agent_forward = ?, updated_at = ?
WHERE id = ? AND account_id = ?;
