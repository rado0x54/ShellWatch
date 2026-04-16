CREATE TABLE `oauth_access_tokens` (
	`id` text PRIMARY KEY NOT NULL,
	`payload` text NOT NULL,
	`grant_id` text,
	`user_code` text,
	`uid` text,
	`consumed_at` text,
	`expires_at` text,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `oauth_access_tokens_grant_id_idx` ON `oauth_access_tokens` (`grant_id`);--> statement-breakpoint
CREATE INDEX `oauth_access_tokens_expires_at_idx` ON `oauth_access_tokens` (`expires_at`);--> statement-breakpoint
CREATE TABLE `oauth_authorization_codes` (
	`id` text PRIMARY KEY NOT NULL,
	`payload` text NOT NULL,
	`grant_id` text,
	`user_code` text,
	`uid` text,
	`consumed_at` text,
	`expires_at` text,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `oauth_authorization_codes_grant_id_idx` ON `oauth_authorization_codes` (`grant_id`);--> statement-breakpoint
CREATE INDEX `oauth_authorization_codes_expires_at_idx` ON `oauth_authorization_codes` (`expires_at`);--> statement-breakpoint
CREATE TABLE `oauth_clients` (
	`id` text PRIMARY KEY NOT NULL,
	`payload` text NOT NULL,
	`grant_id` text,
	`user_code` text,
	`uid` text,
	`consumed_at` text,
	`expires_at` text,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `oauth_grants` (
	`id` text PRIMARY KEY NOT NULL,
	`payload` text NOT NULL,
	`grant_id` text,
	`user_code` text,
	`uid` text,
	`consumed_at` text,
	`expires_at` text,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `oauth_interactions` (
	`id` text PRIMARY KEY NOT NULL,
	`payload` text NOT NULL,
	`grant_id` text,
	`user_code` text,
	`uid` text,
	`consumed_at` text,
	`expires_at` text,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `oauth_interactions_expires_at_idx` ON `oauth_interactions` (`expires_at`);--> statement-breakpoint
CREATE TABLE `oauth_refresh_tokens` (
	`id` text PRIMARY KEY NOT NULL,
	`payload` text NOT NULL,
	`grant_id` text,
	`user_code` text,
	`uid` text,
	`consumed_at` text,
	`expires_at` text,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `oauth_refresh_tokens_grant_id_idx` ON `oauth_refresh_tokens` (`grant_id`);--> statement-breakpoint
CREATE INDEX `oauth_refresh_tokens_expires_at_idx` ON `oauth_refresh_tokens` (`expires_at`);--> statement-breakpoint
CREATE TABLE `oauth_registration_access_tokens` (
	`id` text PRIMARY KEY NOT NULL,
	`payload` text NOT NULL,
	`grant_id` text,
	`user_code` text,
	`uid` text,
	`consumed_at` text,
	`expires_at` text,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `oauth_registration_access_tokens_expires_at_idx` ON `oauth_registration_access_tokens` (`expires_at`);--> statement-breakpoint
CREATE TABLE `oauth_replay_detection` (
	`id` text PRIMARY KEY NOT NULL,
	`payload` text NOT NULL,
	`grant_id` text,
	`user_code` text,
	`uid` text,
	`consumed_at` text,
	`expires_at` text,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `oauth_replay_detection_expires_at_idx` ON `oauth_replay_detection` (`expires_at`);--> statement-breakpoint
CREATE TABLE `oauth_sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`payload` text NOT NULL,
	`grant_id` text,
	`user_code` text,
	`uid` text,
	`consumed_at` text,
	`expires_at` text,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `oauth_sessions_grant_id_idx` ON `oauth_sessions` (`grant_id`);--> statement-breakpoint
CREATE INDEX `oauth_sessions_uid_idx` ON `oauth_sessions` (`uid`);--> statement-breakpoint
CREATE INDEX `oauth_sessions_expires_at_idx` ON `oauth_sessions` (`expires_at`);--> statement-breakpoint
CREATE TABLE `oauth_signing_keys` (
	`kid` text PRIMARY KEY NOT NULL,
	`alg` text NOT NULL,
	`private_jwk_ciphertext` text NOT NULL,
	`public_jwk` text NOT NULL,
	`created_at` text NOT NULL,
	`retired_at` text
);
