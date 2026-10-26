-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- Endpoint queries (Phase 3). Every account-owned query takes account_id in
-- SQL (W13). Keep pure ASCII (sqlc offset bug on multi-byte chars).

-- name: ListEndpointsForAccount :many
-- enabled filter matches Node (findAllForAccount, endpoint-repo.ts:87): a
-- soft-deleted endpoint is hidden from lists. Get-by-id deliberately does NOT
-- filter (Node parity: post-delete session create / PUT by id still work).
SELECT id, account_id, label, host, port, username, user_verification, description, agent_forward,
  host_key_type, host_key_fingerprint, host_key_pinned_at, host_key_pinned_by
FROM endpoints WHERE account_id = ? AND enabled = 1 ORDER BY created_at, id;

-- name: GetEndpointForAccount :one
SELECT id, account_id, label, host, port, username, user_verification, description, agent_forward,
  host_key_type, host_key_fingerprint, host_key_pinned_at, host_key_pinned_by
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
-- A host or port change invalidates the pinned host key (#241): the CASE
-- expressions see the row's pre-update values, so the pin survives only when
-- the new address equals the stored one. Clearing happens in the same
-- statement as the write - no window where the old pin covers a new address.
UPDATE endpoints SET
  host_key_type = CASE WHEN host = sqlc.arg(host) AND port = sqlc.arg(port) THEN host_key_type ELSE NULL END,
  host_key = CASE WHEN host = sqlc.arg(host) AND port = sqlc.arg(port) THEN host_key ELSE NULL END,
  host_key_fingerprint = CASE WHEN host = sqlc.arg(host) AND port = sqlc.arg(port) THEN host_key_fingerprint ELSE NULL END,
  host_key_pinned_at = CASE WHEN host = sqlc.arg(host) AND port = sqlc.arg(port) THEN host_key_pinned_at ELSE NULL END,
  host_key_pinned_by = CASE WHEN host = sqlc.arg(host) AND port = sqlc.arg(port) THEN host_key_pinned_by ELSE NULL END,
  label = sqlc.arg(label), host = sqlc.arg(host), port = sqlc.arg(port), username = sqlc.arg(username),
  user_verification = sqlc.arg(user_verification), description = sqlc.arg(description),
  agent_forward = sqlc.arg(agent_forward), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND account_id = sqlc.arg(account_id);

-- name: GetEndpointHostKey :one
-- Connection-time pin lookup (#241). By id only: the endpoint was already
-- resolved account-scoped before any dial. host/port let PinHostKey tell a
-- lost CAS apart from an address change.
SELECT host, port, host_key_type, host_key, host_key_fingerprint, host_key_pinned_at, host_key_pinned_by
FROM endpoints WHERE id = ?;

-- name: PinEndpointHostKey :execrows
-- Compare-and-set (#241): writes only when no pin exists AND the endpoint
-- still points at the address the key was observed at - an approval that
-- waited while the endpoint moved to a new host/port must not vouch for it.
-- 0 rows means a pin landed first or the address changed; the caller
-- disambiguates via GetEndpointHostKey.
UPDATE endpoints SET host_key_type = ?, host_key = ?, host_key_fingerprint = ?,
  host_key_pinned_at = ?, host_key_pinned_by = ?, updated_at = ?
WHERE id = ? AND host_key_fingerprint IS NULL AND host = ? AND port = ?;

-- name: ClearEndpointHostKey :execrows
UPDATE endpoints SET host_key_type = NULL, host_key = NULL, host_key_fingerprint = NULL,
  host_key_pinned_at = NULL, host_key_pinned_by = NULL, updated_at = ?
WHERE id = ? AND account_id = ? AND host_key_fingerprint IS NOT NULL;

-- name: ListEndpointsByAddress :many
-- Config-file pin provisioning (#241): seedAdminEndpoints carry no stable id,
-- so a config hostKey is matched to DB rows by address tuple.
SELECT id, host_key_fingerprint FROM endpoints
WHERE account_id = ? AND host = ? AND port = ? AND username = ? AND enabled = 1;
