CREATE TABLE `api_keys` (
	`id` text PRIMARY KEY NOT NULL,
	`label` text NOT NULL,
	`key_hash` text NOT NULL,
	`key_prefix` text NOT NULL,
	`scopes` text NOT NULL,
	`endpoints` text,
	`enabled` integer DEFAULT true NOT NULL,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `api_keys_key_hash_unique` ON `api_keys` (`key_hash`);--> statement-breakpoint
CREATE TABLE `audit_events` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`timestamp` text NOT NULL,
	`session_id` text,
	`event_type` text NOT NULL,
	`data` text
);
--> statement-breakpoint
CREATE TABLE `endpoints` (
	`id` text PRIMARY KEY NOT NULL,
	`label` text NOT NULL,
	`host` text NOT NULL,
	`port` integer DEFAULT 22 NOT NULL,
	`username` text NOT NULL,
	`private_key_path` text NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `guardrail_rules` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`pattern` text NOT NULL,
	`action` text NOT NULL,
	`message` text,
	`enabled` integer DEFAULT true NOT NULL,
	`priority` integer DEFAULT 0 NOT NULL,
	`endpoint_id` text,
	`source` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `guardrail_rules_name_unique` ON `guardrail_rules` (`name`);--> statement-breakpoint
CREATE TABLE `session_history` (
	`session_id` text PRIMARY KEY NOT NULL,
	`endpoint_id` text NOT NULL,
	`source` text NOT NULL,
	`status` text NOT NULL,
	`created_at` text NOT NULL,
	`closed_at` text,
	`duration_ms` integer
);
