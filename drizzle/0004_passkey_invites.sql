CREATE TABLE `passkey_invites` (
	`id` text PRIMARY KEY NOT NULL,
	`account_id` text NOT NULL,
	`token` text NOT NULL,
	`label` text NOT NULL,
	`expires_at` text NOT NULL,
	`consumed_at` text,
	`revoked_at` text,
	`credential_id` text,
	`created_at` text NOT NULL,
	FOREIGN KEY (`account_id`) REFERENCES `accounts`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`credential_id`) REFERENCES `webauthn_credentials`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE UNIQUE INDEX `passkey_invites_token_unique` ON `passkey_invites` (`token`);--> statement-breakpoint
ALTER TABLE `webauthn_credentials` ADD `state` text DEFAULT 'active' NOT NULL;