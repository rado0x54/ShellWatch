ALTER TABLE `endpoints` ADD `agent_forward` integer DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE `accounts` DROP COLUMN `agent_forward`;