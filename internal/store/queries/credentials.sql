-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- WebAuthn credential queries (Phase 2). store.Credentials is the SOLE owner
-- of webauthn_credentials (fixes W8; the Node backend touched it from six
-- files). Keep this file pure ASCII (sqlc offset bug on multi-byte chars).

-- name: HasPasskeys :one
SELECT EXISTS(SELECT 1 FROM webauthn_credentials) AS has_passkeys;

-- name: InsertCredential :exec
INSERT INTO webauthn_credentials (
  id, account_id, credential_id, public_key, counter, transports, label,
  public_key_openssh, state, revoked, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?);

-- name: ListActiveCredentialIDsForAccount :many
SELECT credential_id FROM webauthn_credentials
WHERE account_id = ? AND revoked = 0;

-- name: ListAllActiveCredentialIDs :many
SELECT credential_id FROM webauthn_credentials
WHERE revoked = 0 AND state = 'active';

-- name: ListActiveCredentialLabelsForAccount :many
SELECT label FROM webauthn_credentials WHERE account_id = ?;

-- name: FindCredentialByCredentialID :one
SELECT id, account_id, credential_id, public_key, counter, transports, revoked, state
FROM webauthn_credentials WHERE credential_id = ?;

-- name: UpdateCredentialCounter :exec
UPDATE webauthn_credentials SET counter = ?, last_used_at = ? WHERE id = ?;

-- name: FindCredentialByIDAndAccount :one
SELECT id, state, revoked FROM webauthn_credentials
WHERE id = ? AND account_id = ?;

-- name: SetCredentialState :exec
UPDATE webauthn_credentials SET state = ? WHERE id = ?;

-- name: ListActiveCredentialsForAuth :many
SELECT id, credential_id, public_key_openssh, label FROM webauthn_credentials
WHERE account_id = ? AND revoked = 0 AND state = 'active';

-- name: ListCredentialsForAccountFull :many
SELECT id, credential_id, public_key, public_key_openssh, label, revoked, state, created_at, last_used_at
FROM webauthn_credentials WHERE account_id = ?;

-- name: UpdateCredentialLabel :exec
UPDATE webauthn_credentials SET label = ? WHERE id = ? AND account_id = ?;

-- name: LabelConflictExists :one
SELECT EXISTS(SELECT 1 FROM webauthn_credentials WHERE account_id = ? AND label = ? AND id != ?) AS has_conflict;

-- name: RevokeCredentialByID :exec
UPDATE webauthn_credentials SET revoked = 1 WHERE id = ?;

-- name: CountActiveCredentials :one
SELECT COUNT(*) AS n FROM webauthn_credentials WHERE account_id = ? AND revoked = 0 AND state = 'active';

-- name: ExportActiveCredentials :many
SELECT credential_id, public_key, counter, transports, label
FROM webauthn_credentials WHERE account_id = ? AND revoked = 0 AND state = 'active';
