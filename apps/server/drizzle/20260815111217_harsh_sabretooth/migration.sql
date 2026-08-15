CREATE TABLE `invitations` (
	`id` text PRIMARY KEY,
	`project_id` text NOT NULL,
	`token_hash` text NOT NULL,
	`role` text NOT NULL,
	`inviter_user_id` text NOT NULL,
	`status` text NOT NULL,
	`expires_at` integer NOT NULL,
	`invitee_user_id` text,
	`invitee_enc_pub` text,
	`invitee_sig_pub` text,
	`accept_signature` text,
	`accepted_at` integer,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `inv_token_hash` ON `invitations` (`token_hash`);--> statement-breakpoint
CREATE INDEX `inv_project_status` ON `invitations` (`project_id`,`status`);--> statement-breakpoint
CREATE INDEX `inv_project_created` ON `invitations` (`project_id`,`created_at`);