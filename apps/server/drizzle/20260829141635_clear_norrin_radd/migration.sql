CREATE TABLE `project_members` (
	`project_id` text NOT NULL,
	`user_id` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `project_members_pk` PRIMARY KEY(`project_id`, `user_id`)
);
--> statement-breakpoint
CREATE INDEX `pm_user_project` ON `project_members` (`user_id`,`project_id`);