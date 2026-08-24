CREATE TABLE `login_failed_windows` (
	`bucket` text PRIMARY KEY,
	`window_start` integer NOT NULL,
	`recorded_count` integer DEFAULT 0 NOT NULL,
	`suppressed_count` integer DEFAULT 0 NOT NULL
);
