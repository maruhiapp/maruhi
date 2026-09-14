-- ES(2026-09-14 — AUTH_SPEC §15-2 / CRYPTO_SPEC §6.5): 招待行に付与予定 scope の 2 列を加える。
-- 発行署名が scope を覆う新形式の発行文だけが受諾・add_member に使えるため、旧行
-- (scope を含まない発行文)は互換経路を持たず、すべて消してから表を再構築する
-- (ES 導入前に受理されたチェーンも新規則で無効になる — CRYPTO_SPEC §6.2。
-- 既存プロジェクトは再作成する: docs/SELF_HOSTING.md "Updates")。
-- SQLite は NOT NULL 列の ADD COLUMN に非 NULL 既定値を要求するため、既定値を
-- 持たない 2 列は 20260914005050_damp_redwing と同じ表再構築で加える。
DELETE FROM `invitations`;--> statement-breakpoint
CREATE TABLE `__new_invitations` (
	`id` text PRIMARY KEY,
	`project_id` text NOT NULL,
	`link_pub` text NOT NULL,
	`head_hash` text NOT NULL,
	`head_seq` integer NOT NULL,
	`issue_signature` text NOT NULL,
	`role` text NOT NULL,
	`scope_kind` text NOT NULL,
	`scope_environments` text NOT NULL,
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
DROP TABLE `invitations`;--> statement-breakpoint
ALTER TABLE `__new_invitations` RENAME TO `invitations`;--> statement-breakpoint
CREATE UNIQUE INDEX `inv_link_pub` ON `invitations` (`link_pub`);--> statement-breakpoint
CREATE INDEX `inv_project_status` ON `invitations` (`project_id`,`status`);--> statement-breakpoint
CREATE INDEX `inv_project_created` ON `invitations` (`project_id`,`created_at`);
