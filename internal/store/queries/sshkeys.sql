-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- SSH file-key metadata (auto-discovered from the key directory). Keep pure
-- ASCII (sqlc offset bug on multi-byte chars).

-- name: ListSSHKeys :many
SELECT id, label, type, fingerprint FROM ssh_keys WHERE enabled = 1 ORDER BY created_at, id;

-- name: GetSSHKey :one
SELECT id, label, type, public_key, fingerprint FROM ssh_keys WHERE id = ?;

-- name: ListSSHKeysFull :many
SELECT id, label, type, public_key, fingerprint, enabled, created_at, last_used_at
FROM ssh_keys ORDER BY created_at, id;

-- name: SSHKeyFingerprintExists :one
SELECT EXISTS(SELECT 1 FROM ssh_keys WHERE fingerprint = ?) AS present;

-- name: InsertFileKey :exec
INSERT INTO ssh_keys (id, label, type, public_key, fingerprint, enabled, created_at, updated_at)
VALUES (?, ?, 'file', ?, ?, 1, ?, ?);
