CREATE TABLE `cli_login_flows` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`status` text NOT NULL,
	`token_name` text NOT NULL,
	`scopes` text NOT NULL,
	`expires_in_days` integer NOT NULL,
	`user_code` text NOT NULL,
	`ticket_hash` text NOT NULL,
	`expires_at` integer NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_cli_login_flows_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `flow_signing_keys` (
	`id` text PRIMARY KEY,
	`key_hex` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `clf_expires` ON `cli_login_flows` (`expires_at`);