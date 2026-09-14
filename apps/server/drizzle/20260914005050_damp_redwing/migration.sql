-- IV 改訂前の行(link_pub 無し)は受諾不能で、互換経路を持たない(2026-09-13 所有者裁定)。
-- 表再構築で NOT NULL にする前に消す(hosted の利用者は所有者のみ — 2026-09-14 所有者裁定)
DELETE FROM `invitations` WHERE `link_pub` IS NULL;--> statement-breakpoint
PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_invitations` (
	`id` text PRIMARY KEY,
	`project_id` text NOT NULL,
	`link_pub` text NOT NULL,
	`head_hash` text NOT NULL,
	`head_seq` integer NOT NULL,
	`issue_signature` text NOT NULL,
	`role` text NOT NULL,
	`inviter_user_id` text NOT NULL,
	`status` text NOT NULL,
	`expires_at` integer NOT NULL,
	`invitee_user_id` text,
	`invitee_enc_pub` text,
	`invitee_sig_pub` text,
	`accept_signature` text,
	`link_signature` text,
	`accepted_at` integer,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
INSERT INTO `__new_invitations`(`id`, `project_id`, `link_pub`, `head_hash`, `head_seq`, `issue_signature`, `role`, `inviter_user_id`, `status`, `expires_at`, `invitee_user_id`, `invitee_enc_pub`, `invitee_sig_pub`, `accept_signature`, `link_signature`, `accepted_at`, `created_at`) SELECT `id`, `project_id`, `link_pub`, `head_hash`, `head_seq`, `issue_signature`, `role`, `inviter_user_id`, `status`, `expires_at`, `invitee_user_id`, `invitee_enc_pub`, `invitee_sig_pub`, `accept_signature`, `link_signature`, `accepted_at`, `created_at` FROM `invitations`;--> statement-breakpoint
DROP TABLE `invitations`;--> statement-breakpoint
ALTER TABLE `__new_invitations` RENAME TO `invitations`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
DROP INDEX IF EXISTS `inv_token_hash`;--> statement-breakpoint
CREATE UNIQUE INDEX `inv_link_pub` ON `invitations` (`link_pub`);--> statement-breakpoint
CREATE INDEX `inv_project_status` ON `invitations` (`project_id`,`status`);--> statement-breakpoint
CREATE INDEX `inv_project_created` ON `invitations` (`project_id`,`created_at`);