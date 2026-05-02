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
	FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`) ON UPDATE no action ON DELETE cascade
);
