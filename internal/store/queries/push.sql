-- SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
-- Web Push subscriptions (settings/notifications). Keep pure ASCII.

-- name: FindPushByEndpoint :one
SELECT id, account_id FROM push_subscriptions WHERE endpoint = ?;

-- name: InsertPushSub :exec
INSERT INTO push_subscriptions (id, account_id, endpoint, p256dh, auth, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: RotatePushSub :exec
UPDATE push_subscriptions SET p256dh = ?, auth = ?, updated_at = ? WHERE endpoint = ? AND account_id = ?;

-- name: DeletePushByEndpoint :exec
DELETE FROM push_subscriptions WHERE account_id = ? AND endpoint = ?;
