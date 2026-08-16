ALTER TABLE `org_audit_events` ADD `row_id` text;--> statement-breakpoint
ALTER TABLE `user_audit_events` ADD `row_id` text;--> statement-breakpoint
CREATE UNIQUE INDEX `oae_row_id` ON `org_audit_events` (`row_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `uae_row_id` ON `user_audit_events` (`row_id`);--> statement-breakpoint
-- 既存行の backfill(randomblob は行ごとに評価される。新規行はアプリ側で採番)
UPDATE `org_audit_events` SET `row_id` = lower(hex(randomblob(16))) WHERE `row_id` IS NULL;--> statement-breakpoint
UPDATE `user_audit_events` SET `row_id` = lower(hex(randomblob(16))) WHERE `row_id` IS NULL;
