CREATE TABLE `org_audit_events` (
	`seq` integer PRIMARY KEY AUTOINCREMENT,
	`server_ts` integer NOT NULL,
	`event` text NOT NULL,
	`actor_type` text NOT NULL,
	`actor_user_id` text,
	`actor_api_token_id` text,
	`target_user_id` text,
	`org_id` text,
	`project_id` text,
	`payload` text
);
--> statement-breakpoint
CREATE TABLE `user_audit_events` (
	`seq` integer PRIMARY KEY AUTOINCREMENT,
	`server_ts` integer NOT NULL,
	`event` text NOT NULL,
	`actor_type` text NOT NULL,
	`actor_user_id` text,
	`actor_api_token_id` text,
	`target_user_id` text,
	`org_id` text,
	`project_id` text,
	`payload` text
);
--> statement-breakpoint
CREATE INDEX `oae_actor` ON `org_audit_events` (`actor_user_id`,`seq`);--> statement-breakpoint
CREATE INDEX `oae_target` ON `org_audit_events` (`target_user_id`,`seq`);--> statement-breakpoint
CREATE INDEX `oae_event` ON `org_audit_events` (`event`,`seq`);--> statement-breakpoint
CREATE INDEX `oae_org` ON `org_audit_events` (`org_id`,`seq`);--> statement-breakpoint
CREATE INDEX `uae_actor` ON `user_audit_events` (`actor_user_id`,`seq`);--> statement-breakpoint
CREATE INDEX `uae_target` ON `user_audit_events` (`target_user_id`,`seq`);--> statement-breakpoint
CREATE INDEX `uae_event` ON `user_audit_events` (`event`,`seq`);