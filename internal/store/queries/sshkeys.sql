-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- SSH file-key metadata (auto-discovered from the key directory). Keep pure
-- ASCII (sqlc offset bug on multi-byte chars).

-- name: ListSSHKeys :many
SELECT id, label, type, fingerprint FROM ssh_keys WHERE enabled = 1 ORDER BY created_at, id;

-- name: GetSSHKey :one
SELECT id, label, type, public_key, fingerprint FROM ssh_keys WHERE id = ?;
