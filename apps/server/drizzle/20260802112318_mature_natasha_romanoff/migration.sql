CREATE TABLE `api_tokens` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`name` text NOT NULL,
	`token_hash` text NOT NULL,
	`token_prefix` text NOT NULL,
	`scopes` text NOT NULL,
	`expires_at` integer,
	`created_at` integer NOT NULL,
	`last_used_at` integer,
	CONSTRAINT `fk_api_tokens_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `linked_identities` (
	`user_id` text NOT NULL,
	`provider` text NOT NULL,
	`provider_user_id` text NOT NULL,
	`provider_login` text,
	`linked_at` integer NOT NULL,
	CONSTRAINT `linked_identities_pk` PRIMARY KEY(`provider`, `provider_user_id`),
	CONSTRAINT `fk_linked_identities_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `memberships` (
	`org_id` text NOT NULL,
	`user_id` text NOT NULL,
	`role` text NOT NULL,
	CONSTRAINT `memberships_pk` PRIMARY KEY(`org_id`, `user_id`),
	CONSTRAINT `fk_memberships_org_id_organizations_id_fk` FOREIGN KEY (`org_id`) REFERENCES `organizations`(`id`),
	CONSTRAINT `fk_memberships_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `organizations` (
	`id` text PRIMARY KEY,
	`slug` text NOT NULL,
	`name` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `projects` (
	`id` text PRIMARY KEY,
	`org_id` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_projects_org_id_organizations_id_fk` FOREIGN KEY (`org_id`) REFERENCES `organizations`(`id`)
);
--> statement-breakpoint
CREATE TABLE `sessions` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`auth_method` text NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`last_used_at` integer NOT NULL,
	CONSTRAINT `fk_sessions_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `users` (
	`id` text PRIMARY KEY,
	`email` text,
	`email_verified` integer DEFAULT 0 NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `tok_hash` ON `api_tokens` (`token_hash`);--> statement-breakpoint
CREATE INDEX `tok_user` ON `api_tokens` (`user_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `tok_user_name` ON `api_tokens` (`user_id`,`name`);--> statement-breakpoint
CREATE INDEX `li_user` ON `linked_identities` (`user_id`);--> statement-breakpoint
CREATE INDEX `mem_user` ON `memberships` (`user_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `org_slug` ON `organizations` (`slug`);--> statement-breakpoint
CREATE INDEX `proj_org` ON `projects` (`org_id`);--> statement-breakpoint
CREATE INDEX `sess_user` ON `sessions` (`user_id`);--> statement-breakpoint
CREATE INDEX `sess_expires` ON `sessions` (`expires_at`);