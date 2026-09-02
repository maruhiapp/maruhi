CREATE TABLE `deployment_settings` (
	`key` text PRIMARY KEY,
	`value` text NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `signup_invites` (
	`id` text PRIMARY KEY,
	`token_hash` text NOT NULL,
	`status` text NOT NULL,
	`expires_at` integer NOT NULL,
	`created_at` integer NOT NULL,
	`used_by_user_id` text,
	`used_at` integer
);
--> statement-breakpoint
CREATE UNIQUE INDEX `sgn_token_hash` ON `signup_invites` (`token_hash`);