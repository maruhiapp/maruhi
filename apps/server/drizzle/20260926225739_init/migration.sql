CREATE TABLE `api_tokens` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`name` text NOT NULL,
	`token_hash` text NOT NULL,
	`token_prefix` text NOT NULL,
	`scopes` text NOT NULL,
	`expires_at` integer NOT NULL,
	`created_at` integer NOT NULL,
	`last_used_at` integer,
	CONSTRAINT `fk_api_tokens_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `cli_login_flows` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`status` text NOT NULL,
	`token_name` text NOT NULL,
	`scopes` text NOT NULL,
	`expires_in_days` integer NOT NULL,
	`user_code` text NOT NULL,
	`ticket_hash` text NOT NULL,
	`expires_at` integer NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_cli_login_flows_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `deployment_settings` (
	`key` text PRIMARY KEY,
	`value` text NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
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
	`created_at` integer NOT NULL,
	`token_id` text,
	CONSTRAINT `devices_pk` PRIMARY KEY(`user_id`, `key_fingerprint_hex`),
	CONSTRAINT `fk_devices_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `flow_signing_keys` (
	`id` text PRIMARY KEY,
	`key_hex` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
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
	CONSTRAINT `guardian_shares_pk` PRIMARY KEY(`group_id`, `share_index`, `guardian_key_fingerprint_hex`),
	CONSTRAINT `fk_guardian_shares_group_id_guardian_groups_id_fk` FOREIGN KEY (`group_id`) REFERENCES `guardian_groups`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_guardian_shares_guardian_user_id_users_id_fk` FOREIGN KEY (`guardian_user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `invitations` (
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
CREATE TABLE `key_handoff_approvals` (
	`request_id` text NOT NULL,
	`source` text NOT NULL,
	`share_index` integer NOT NULL,
	`approver_user_id` text NOT NULL,
	`approver_key_fingerprint_hex` text NOT NULL,
	`enc_hex` text NOT NULL,
	`ciphertext_hex` text NOT NULL,
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
CREATE TABLE `linked_identities` (
	`user_id` text NOT NULL,
	`provider` text NOT NULL,
	`provider_user_id` text NOT NULL,
	`provider_login` text,
	`linked_at` integer NOT NULL,
	CONSTRAINT `linked_identities_pk` PRIMARY KEY(`provider`, `provider_user_id`),
	CONSTRAINT `fk_linked_identities_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `login_failed_windows` (
	`bucket` text PRIMARY KEY,
	`window_start` integer NOT NULL,
	`recorded_count` integer DEFAULT 0 NOT NULL,
	`suppressed_count` integer DEFAULT 0 NOT NULL
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
CREATE TABLE `memberships` (
	`org_id` text NOT NULL,
	`user_id` text NOT NULL,
	`role` text NOT NULL,
	CONSTRAINT `memberships_pk` PRIMARY KEY(`org_id`, `user_id`),
	CONSTRAINT `fk_memberships_org_id_organizations_id_fk` FOREIGN KEY (`org_id`) REFERENCES `organizations`(`id`),
	CONSTRAINT `fk_memberships_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `ops_backups` (
	`project_id` text PRIMARY KEY,
	`do_id_hex` text NOT NULL,
	`last_attempt_at` integer NOT NULL,
	`last_success_at` integer,
	`last_object_key` text,
	`last_bytes` integer,
	`last_audit_seq` integer,
	`last_chain_seq` integer,
	`last_attestation_mark` integer,
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
--> statement-breakpoint
CREATE TABLE `org_audit_events` (
	`seq` integer PRIMARY KEY AUTOINCREMENT,
	`row_id` text NOT NULL,
	`server_ts` integer NOT NULL,
	`event` text NOT NULL,
	`actor_type` text NOT NULL,
	`actor_user_id` text,
	`actor_api_token_id` text,
	`target_user_id` text,
	`org_id` text,
	`project_id` text,
	`payload` text
);
--> statement-breakpoint
CREATE TABLE `organizations` (
	`id` text PRIMARY KEY,
	`slug` text NOT NULL,
	`name` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `project_members` (
	`project_id` text NOT NULL,
	`user_id` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `project_members_pk` PRIMARY KEY(`project_id`, `user_id`)
);
--> statement-breakpoint
CREATE TABLE `projects` (
	`id` text PRIMARY KEY,
	`org_id` text NOT NULL,
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_projects_org_id_organizations_id_fk` FOREIGN KEY (`org_id`) REFERENCES `organizations`(`id`)
);
--> statement-breakpoint
CREATE TABLE `recovery_wraps` (
	`user_id` text PRIMARY KEY,
	`suite` text NOT NULL,
	`nonce_hex` text NOT NULL,
	`ciphertext_hex` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	CONSTRAINT `fk_recovery_wraps_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `sessions` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`auth_method` text NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`last_used_at` integer NOT NULL,
	CONSTRAINT `fk_sessions_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
);
--> statement-breakpoint
CREATE TABLE `signup_invites` (
	`id` text PRIMARY KEY,
	`token_hash` text NOT NULL,
	`status` text NOT NULL,
	`expires_at` integer NOT NULL,
	`created_at` integer NOT NULL,
	`used_by_user_id` text,
	`used_at` integer
);
--> statement-breakpoint
CREATE TABLE `user_audit_events` (
	`seq` integer PRIMARY KEY AUTOINCREMENT,
	`row_id` text NOT NULL,
	`server_ts` integer NOT NULL,
	`event` text NOT NULL,
	`actor_type` text NOT NULL,
	`actor_user_id` text,
	`actor_api_token_id` text,
	`target_user_id` text,
	`org_id` text,
	`project_id` text,
	`payload` text
);
--> statement-breakpoint
CREATE TABLE `users` (
	`id` text PRIMARY KEY,
	`email` text,
	`email_verified` integer DEFAULT 0 NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `tok_hash` ON `api_tokens` (`token_hash`);--> statement-breakpoint
CREATE INDEX `tok_user` ON `api_tokens` (`user_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `tok_user_name` ON `api_tokens` (`user_id`,`name`);--> statement-breakpoint
CREATE INDEX `clf_expires` ON `cli_login_flows` (`expires_at`);--> statement-breakpoint
CREATE INDEX `gg_user` ON `guardian_groups` (`user_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `gs_group_guardian_device` ON `guardian_shares` (`group_id`,`guardian_user_id`,`guardian_key_fingerprint_hex`);--> statement-breakpoint
CREATE INDEX `gs_guardian` ON `guardian_shares` (`guardian_user_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `inv_link_pub` ON `invitations` (`link_pub`);--> statement-breakpoint
CREATE INDEX `inv_project_status` ON `invitations` (`project_id`,`status`);--> statement-breakpoint
CREATE INDEX `inv_project_created` ON `invitations` (`project_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `khr_user` ON `key_handoff_requests` (`user_id`);--> statement-breakpoint
CREATE INDEX `khr_expires` ON `key_handoff_requests` (`expires_at`);--> statement-breakpoint
CREATE INDEX `li_user` ON `linked_identities` (`user_id`);--> statement-breakpoint
CREATE INDEX `mkw_user` ON `master_key_wraps` (`user_id`);--> statement-breakpoint
CREATE INDEX `mem_user` ON `memberships` (`user_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `oae_row_id` ON `org_audit_events` (`row_id`);--> statement-breakpoint
CREATE INDEX `oae_actor` ON `org_audit_events` (`actor_user_id`,`seq`);--> statement-breakpoint
CREATE INDEX `oae_target` ON `org_audit_events` (`target_user_id`,`seq`);--> statement-breakpoint
CREATE INDEX `oae_event` ON `org_audit_events` (`event`,`seq`);--> statement-breakpoint
CREATE INDEX `oae_org` ON `org_audit_events` (`org_id`,`seq`);--> statement-breakpoint
CREATE INDEX `oae_project` ON `org_audit_events` (`project_id`,`seq`);--> statement-breakpoint
CREATE UNIQUE INDEX `org_slug` ON `organizations` (`slug`);--> statement-breakpoint
CREATE INDEX `pm_user_project` ON `project_members` (`user_id`,`project_id`);--> statement-breakpoint
CREATE INDEX `proj_org` ON `projects` (`org_id`);--> statement-breakpoint
CREATE INDEX `sess_user` ON `sessions` (`user_id`);--> statement-breakpoint
CREATE INDEX `sess_expires` ON `sessions` (`expires_at`);--> statement-breakpoint
CREATE UNIQUE INDEX `sgn_token_hash` ON `signup_invites` (`token_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `uae_row_id` ON `user_audit_events` (`row_id`);--> statement-breakpoint
CREATE INDEX `uae_actor` ON `user_audit_events` (`actor_user_id`,`seq`);--> statement-breakpoint
CREATE INDEX `uae_target` ON `user_audit_events` (`target_user_id`,`seq`);--> statement-breakpoint
CREATE INDEX `uae_event` ON `user_audit_events` (`event`,`seq`);