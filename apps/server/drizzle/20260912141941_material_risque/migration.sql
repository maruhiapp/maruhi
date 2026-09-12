CREATE TABLE `guardian_groups` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`mode` text NOT NULL,
	`suite` text NOT NULL,
	`nonce_hex` text NOT NULL,
	`ciphertext_hex` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_guardian_groups_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `guardian_shares` (
	`group_id` text NOT NULL,
	`share_index` integer NOT NULL,
	`guardian_user_id` text NOT NULL,
	`guardian_enc_pub_hex` text NOT NULL,
	`guardian_key_fingerprint_hex` text NOT NULL,
	`enc_hex` text NOT NULL,
	`ciphertext_hex` text NOT NULL,
	CONSTRAINT `guardian_shares_pk` PRIMARY KEY(`group_id`, `share_index`),
	CONSTRAINT `fk_guardian_shares_group_id_guardian_groups_id_fk` FOREIGN KEY (`group_id`) REFERENCES `guardian_groups`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_guardian_shares_guardian_user_id_users_id_fk` FOREIGN KEY (`guardian_user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `key_handoff_approvals` (
	`request_id` text NOT NULL,
	`source` text NOT NULL,
	`share_index` integer NOT NULL,
	`approver_user_id` text NOT NULL,
	`approver_key_fingerprint_hex` text NOT NULL,
	`enc_hex` text NOT NULL,
	`ciphertext_hex` text NOT NULL,
	`blob_suite` text,
	`blob_nonce_hex` text,
	`blob_ciphertext_hex` text,
	`created_at` integer NOT NULL,
	CONSTRAINT `key_handoff_approvals_pk` PRIMARY KEY(`request_id`, `source`, `share_index`),
	CONSTRAINT `fk_key_handoff_approvals_request_id_key_handoff_requests_id_fk` FOREIGN KEY (`request_id`) REFERENCES `key_handoff_requests`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE TABLE `key_handoff_requests` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`collected_at` integer,
	CONSTRAINT `fk_key_handoff_requests_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `key_wrap_windows` (
	`user_id` text NOT NULL,
	`kind` text NOT NULL,
	`window_start` integer NOT NULL,
	`count` integer DEFAULT 0 NOT NULL,
	CONSTRAINT `key_wrap_windows_pk` PRIMARY KEY(`user_id`, `kind`)
);
--> statement-breakpoint
CREATE TABLE `master_key_wraps` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`kind` text NOT NULL,
	`suite` text NOT NULL,
	`params` text NOT NULL,
	`nonce_hex` text NOT NULL,
	`ciphertext_hex` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	CONSTRAINT `fk_master_key_wraps_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE INDEX `gg_user` ON `guardian_groups` (`user_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `gs_group_guardian` ON `guardian_shares` (`group_id`,`guardian_user_id`);--> statement-breakpoint
CREATE INDEX `gs_guardian` ON `guardian_shares` (`guardian_user_id`);--> statement-breakpoint
CREATE INDEX `khr_user` ON `key_handoff_requests` (`user_id`);--> statement-breakpoint
CREATE INDEX `khr_expires` ON `key_handoff_requests` (`expires_at`);--> statement-breakpoint
CREATE INDEX `mkw_user` ON `master_key_wraps` (`user_id`);