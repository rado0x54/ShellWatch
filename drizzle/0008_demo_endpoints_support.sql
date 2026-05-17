ALTER TABLE `accounts` ADD `show_demo_endpoints` integer DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE `webauthn_credentials` ADD `fingerprint` text;--> statement-breakpoint
ALTER TABLE `ssh_keys` RENAME COLUMN `public_key` TO `public_key_openssh`;
