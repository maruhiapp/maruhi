CREATE TABLE `device_add_requests` (
	`user_id` text NOT NULL,
	`key_fingerprint_hex` text NOT NULL,
	`enc_pub_hex` text NOT NULL,
	`sig_pub_hex` text NOT NULL,
	`label` text NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	CONSTRAINT `device_add_requests_pk` PRIMARY KEY(`user_id`, `key_fingerprint_hex`),
	CONSTRAINT `fk_device_add_requests_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `devices` (
	`user_id` text NOT NULL,
	`key_fingerprint_hex` text NOT NULL,
	`enc_pub_hex` text NOT NULL,
	`sig_pub_hex` text NOT NULL,
	`label` text NOT NULL,
	`token_id` text,
	`created_at` integer NOT NULL,
	CONSTRAINT `devices_pk` PRIMARY KEY(`user_id`, `key_fingerprint_hex`),
	CONSTRAINT `fk_devices_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_guardian_shares` (
	`group_id` text NOT NULL,
	`share_index` integer NOT NULL,
	`guardian_user_id` text NOT NULL,
	`guardian_enc_pub_hex` text NOT NULL,
	`guardian_key_fingerprint_hex` text NOT NULL,
	`enc_hex` text NOT NULL,
	`ciphertext_hex` text NOT NULL,
	CONSTRAINT `guardian_shares_pk` PRIMARY KEY(`group_id`, `share_index`, `guardian_key_fingerprint_hex`),
	CONSTRAINT `fk_guardian_shares_group_id_guardian_groups_id_fk` FOREIGN KEY (`group_id`) REFERENCES `guardian_groups`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_guardian_shares_guardian_user_id_users_id_fk` FOREIGN KEY (`guardian_user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
INSERT INTO `__new_guardian_shares`(`group_id`, `share_index`, `guardian_user_id`, `guardian_enc_pub_hex`, `guardian_key_fingerprint_hex`, `enc_hex`, `ciphertext_hex`) SELECT `group_id`, `share_index`, `guardian_user_id`, `guardian_enc_pub_hex`, `guardian_key_fingerprint_hex`, `enc_hex`, `ciphertext_hex` FROM `guardian_shares`;--> statement-breakpoint
DROP TABLE `guardian_shares`;--> statement-breakpoint
ALTER TABLE `__new_guardian_shares` RENAME TO `guardian_shares`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
DROP INDEX IF EXISTS `gs_group_guardian`;--> statement-breakpoint
CREATE UNIQUE INDEX `gs_group_guardian_device` ON `guardian_shares` (`group_id`,`guardian_user_id`,`guardian_key_fingerprint_hex`);--> statement-breakpoint
CREATE INDEX `gs_guardian` ON `guardian_shares` (`guardian_user_id`);