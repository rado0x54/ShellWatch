-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- Passkey priority order (#308): the user orders their active passkeys in
-- Settings -> Keys; every SSH signing path (endpoint connections, the
-- forwarding agent, /agent-proxy identities) offers them in that order.
-- Lower = tried first. Only active, non-revoked credentials carry a
-- priority; pending and revoked rows are NULL. Gaps are harmless - only the
-- relative order matters. Activation appends (max + 1 of the account),
-- revocation clears it.
-- +goose Up
ALTER TABLE webauthn_credentials ADD COLUMN priority integer;

-- Backfill: per account, active non-revoked credentials ordered by
-- (created_at, id) get 0, 1, 2, ...
UPDATE "webauthn_credentials" SET "priority" = (
	SELECT COUNT(*) FROM "webauthn_credentials" AS w
	WHERE w."account_id" = "webauthn_credentials"."account_id"
	  AND w."revoked" = 0 AND w."state" = 'active'
	  AND (w."created_at" < "webauthn_credentials"."created_at"
	       OR (w."created_at" = "webauthn_credentials"."created_at" AND w."id" < "webauthn_credentials"."id"))
)
WHERE "revoked" = 0 AND "state" = 'active';

-- +goose Down
-- No-op: migrations are forward-only in this project (matching 00001/00002).
