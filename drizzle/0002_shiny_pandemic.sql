DROP TABLE `endpoint_keys`;--> statement-breakpoint
PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_endpoints` (
	`id` text PRIMARY KEY NOT NULL,
	`account_id` text NOT NULL,
	`label` text NOT NULL,
	`host` text NOT NULL,
	`port` integer DEFAULT 22 NOT NULL,
	`username` text NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
INSERT INTO `__new_endpoints`("id", "account_id", "label", "host", "port", "username", "enabled", "created_at", "updated_at") SELECT "id", "account_id", "label", "host", "port", "username", "enabled", "created_at", "updated_at" FROM `endpoints`;--> statement-breakpoint
DROP TABLE `endpoints`;--> statement-breakpoint
ALTER TABLE `__new_endpoints` RENAME TO `endpoints`;--> statement-breakpoint
PRAGMA foreign_keys=ON;