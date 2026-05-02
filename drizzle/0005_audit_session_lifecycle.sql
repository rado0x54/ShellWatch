-- session_history was created in 0001 but never written to by any code path
-- in this repo (grep history confirms no producer landed). Replaced wholesale
-- by audit_session_lifecycle below. Operators running a hand-populated
-- session_history outside this codebase should migrate their data before
-- applying this migration — the DROP is unconditional and not recoverable.
DROP TABLE `session_history`;--> statement-breakpoint
CREATE TABLE `audit_session_lifecycle` (
	`session_id` text PRIMARY KEY NOT NULL,
	`account_id` text NOT NULL,
	`endpoint_id` text NOT NULL,
	`source` text NOT NULL,
	`status` text NOT NULL,
	`created_at` text NOT NULL,
	`closed_at` text,
	`duration_ms` integer,
	`source_ip` text,
	`mcp_reason` text,
	`mcp_client_name` text,
	`mcp_client_version` text,
	`api_key_label` text,
	`api_key_prefix` text,
	`client_hostname` text,
	`client_os` text,
	`client_version` text,
	`close_reason` text,
	FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "audit_session_lifecycle_status_chk" CHECK("status" IN ('open','closed','error')),
	CONSTRAINT "audit_session_lifecycle_source_chk" CHECK("source" IN ('ui','mcp','ssh'))
);
--> statement-breakpoint
CREATE INDEX `audit_session_lifecycle_account_created_idx` ON `audit_session_lifecycle` (`account_id`,`created_at`,`session_id`);--> statement-breakpoint
CREATE INDEX `audit_session_lifecycle_account_endpoint_created_idx` ON `audit_session_lifecycle` (`account_id`,`endpoint_id`,`created_at`,`session_id`);
