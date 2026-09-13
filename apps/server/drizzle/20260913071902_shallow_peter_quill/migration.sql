ALTER TABLE `invitations` ADD `link_pub` text;--> statement-breakpoint
ALTER TABLE `invitations` ADD `head_hash` text;--> statement-breakpoint
ALTER TABLE `invitations` ADD `head_seq` integer;--> statement-breakpoint
ALTER TABLE `invitations` ADD `issue_signature` text;--> statement-breakpoint
ALTER TABLE `invitations` ADD `link_signature` text;--> statement-breakpoint
CREATE UNIQUE INDEX `inv_link_pub` ON `invitations` (`link_pub`);