CREATE TABLE `ops_backups` (
	`project_id` text PRIMARY KEY,
	`do_id_hex` text NOT NULL,
	`last_attempt_at` integer NOT NULL,
	`last_success_at` integer,
	`last_object_key` text,
	`last_bytes` integer,
	`last_audit_seq` integer,
	`last_chain_seq` integer,
	`storage_level` text,
	`consecutive_failures` integer DEFAULT 0 NOT NULL,
	`last_failure_code` text
);
--> statement-breakpoint
CREATE TABLE `ops_counters` (
	`metric` text NOT NULL,
	`window_start` integer NOT NULL,
	`count` integer DEFAULT 0 NOT NULL,
	CONSTRAINT `ops_counters_pk` PRIMARY KEY(`metric`, `window_start`)
);
--> statement-breakpoint
CREATE TABLE `ops_state` (
	`key` text PRIMARY KEY,
	`value` text NOT NULL,
	`updated_at` integer NOT NULL
);
