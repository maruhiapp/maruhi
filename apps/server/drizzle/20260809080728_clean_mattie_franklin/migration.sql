CREATE TABLE `recovery_wraps` (
	`user_id` text PRIMARY KEY,
	`suite` text NOT NULL,
	`nonce_hex` text NOT NULL,
	`ciphertext_hex` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	`fetch_window_start` integer,
	`fetch_count` integer DEFAULT 0 NOT NULL,
	CONSTRAINT `fk_recovery_wraps_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
