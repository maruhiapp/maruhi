import type {
  AuthMethod,
  KeyFingerprintHex,
  OrgId,
  ProjectId,
  ProviderUserId,
  UserId,
} from "@maruhi/core";
import {
  index,
  integer,
  primaryKey,
  sqliteTable,
  text,
  uniqueIndex,
} from "drizzle-orm/sqlite-core";

export const users = sqliteTable("users", {
  id: text("id").$type<UserId>().primaryKey(),
  email: text("email"),
  emailVerified: integer("email_verified").notNull().default(0),
  createdAt: integer("created_at").notNull(),
  updatedAt: integer("updated_at").notNull(),
});

export const linkedIdentities = sqliteTable(
  "linked_identities",
  {
    userId: text("user_id")
      .$type<UserId>()
      .notNull()
      .references(() => users.id),
    provider: text("provider").notNull(),
    providerUserId: text("provider_user_id").$type<ProviderUserId>().notNull(),
    providerLogin: text("provider_login"),
    linkedAt: integer("linked_at").notNull(),
  },
  (t) => [primaryKey({ columns: [t.provider, t.providerUserId] }), index("li_user").on(t.userId)],
);

export const organizations = sqliteTable(
  "organizations",
  {
    id: text("id").$type<OrgId>().primaryKey(),
    slug: text("slug").notNull(),
    name: text("name").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [uniqueIndex("org_slug").on(t.slug)],
);

export const memberships = sqliteTable(
  "memberships",
  {
    orgId: text("org_id")
      .$type<OrgId>()
      .notNull()
      .references(() => organizations.id),
    userId: text("user_id")
      .$type<UserId>()
      .notNull()
      .references(() => users.id),
    role: text("role").notNull(),
  },
  (t) => [primaryKey({ columns: [t.orgId, t.userId] }), index("mem_user").on(t.userId)],
);

export const sessions = sqliteTable(
  "sessions",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .$type<UserId>()
      .notNull()
      .references(() => users.id),
    authMethod: text("auth_method").$type<AuthMethod>().notNull(),
    createdAt: integer("created_at").notNull(),
    expiresAt: integer("expires_at").notNull(),
    lastUsedAt: integer("last_used_at").notNull(),
  },
  (t) => [index("sess_user").on(t.userId), index("sess_expires").on(t.expiresAt)],
);

export const apiTokens = sqliteTable(
  "api_tokens",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .$type<UserId>()
      .notNull()
      .references(() => users.id),
    name: text("name").notNull(),
    tokenHash: text("token_hash").notNull(),
    tokenPrefix: text("token_prefix").notNull(),
    scopes: text("scopes").notNull(),
    expiresAt: integer("expires_at").notNull(),
    createdAt: integer("created_at").notNull(),
    lastUsedAt: integer("last_used_at"),
  },
  (t) => [
    uniqueIndex("tok_hash").on(t.tokenHash),
    index("tok_user").on(t.userId),
    uniqueIndex("tok_user_name").on(t.userId, t.name),
  ],
);

export const deploymentSettings = sqliteTable("deployment_settings", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
  updatedAt: integer("updated_at").notNull(),
});

export const signupInvites = sqliteTable(
  "signup_invites",
  {
    id: text("id").primaryKey(),
    tokenHash: text("token_hash").notNull(),
    status: text("status").notNull(),
    expiresAt: integer("expires_at").notNull(),
    createdAt: integer("created_at").notNull(),
    usedByUserId: text("used_by_user_id").$type<UserId>(),
    usedAt: integer("used_at"),
  },
  (t) => [uniqueIndex("sgn_token_hash").on(t.tokenHash)],
);

export const flowSigningKeys = sqliteTable("flow_signing_keys", {
  id: text("id").primaryKey(),
  keyHex: text("key_hex").notNull(),
  createdAt: integer("created_at").notNull(),
});

export const cliLoginFlows = sqliteTable(
  "cli_login_flows",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .$type<UserId>()
      .notNull()
      .references(() => users.id),
    status: text("status").notNull(),
    tokenName: text("token_name").notNull(),
    scopes: text("scopes").notNull(),
    expiresInDays: integer("expires_in_days").notNull(),
    userCode: text("user_code").notNull(),
    ticketHash: text("ticket_hash").notNull(),
    expiresAt: integer("expires_at").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("clf_expires").on(t.expiresAt)],
);

export const recoveryWraps = sqliteTable("recovery_wraps", {
  userId: text("user_id")
    .$type<UserId>()
    .primaryKey()
    .references(() => users.id),
  suite: text("suite").notNull(),
  nonceHex: text("nonce_hex").notNull(),
  ciphertextHex: text("ciphertext_hex").notNull(),
  createdAt: integer("created_at").notNull(),
  updatedAt: integer("updated_at").notNull(),
});

export const masterKeyWraps = sqliteTable(
  "master_key_wraps",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .$type<UserId>()
      .notNull()
      .references(() => users.id),
    kind: text("kind").notNull(),
    suite: text("suite").notNull(),
    params: text("params").notNull(),
    nonceHex: text("nonce_hex").notNull(),
    ciphertextHex: text("ciphertext_hex").notNull(),
    createdAt: integer("created_at").notNull(),
    updatedAt: integer("updated_at").notNull(),
  },
  (t) => [index("mkw_user").on(t.userId)],
);

export const guardianGroups = sqliteTable(
  "guardian_groups",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .$type<UserId>()
      .notNull()
      .references(() => users.id),
    mode: text("mode").notNull(),
    suite: text("suite").notNull(),
    nonceHex: text("nonce_hex").notNull(),
    ciphertextHex: text("ciphertext_hex").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("gg_user").on(t.userId)],
);

export const guardianShares = sqliteTable(
  "guardian_shares",
  {
    groupId: text("group_id")
      .notNull()
      .references(() => guardianGroups.id, { onDelete: "cascade" }),
    shareIndex: integer("share_index").notNull(),
    guardianUserId: text("guardian_user_id")
      .$type<UserId>()
      .notNull()
      .references(() => users.id),
    guardianEncPubHex: text("guardian_enc_pub_hex").notNull(),
    guardianKeyFingerprintHex: text("guardian_key_fingerprint_hex")
      .$type<KeyFingerprintHex>()
      .notNull(),
    encHex: text("enc_hex").notNull(),
    ciphertextHex: text("ciphertext_hex").notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.groupId, t.shareIndex, t.guardianKeyFingerprintHex] }),
    uniqueIndex("gs_group_guardian_device").on(
      t.groupId,
      t.guardianUserId,
      t.guardianKeyFingerprintHex,
    ),
    index("gs_guardian").on(t.guardianUserId),
  ],
);

const deviceKeyColumns = () => ({
  userId: text("user_id")
    .$type<UserId>()
    .notNull()
    .references(() => users.id),
  keyFingerprintHex: text("key_fingerprint_hex").$type<KeyFingerprintHex>().notNull(),
  encPubHex: text("enc_pub_hex").notNull(),
  sigPubHex: text("sig_pub_hex").notNull(),
  label: text("label").notNull(),
  createdAt: integer("created_at").notNull(),
});

export const devices = sqliteTable(
  "devices",
  {
    ...deviceKeyColumns(),
    tokenId: text("token_id"),
  },
  (t) => [primaryKey({ columns: [t.userId, t.keyFingerprintHex] })],
);

export const deviceAddRequests = sqliteTable(
  "device_add_requests",
  {
    ...deviceKeyColumns(),
    expiresAt: integer("expires_at").notNull(),
  },
  (t) => [primaryKey({ columns: [t.userId, t.keyFingerprintHex] })],
);

export const keyHandoffRequests = sqliteTable(
  "key_handoff_requests",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .$type<UserId>()
      .notNull()
      .references(() => users.id),
    createdAt: integer("created_at").notNull(),
    expiresAt: integer("expires_at").notNull(),
    collectedAt: integer("collected_at"),
  },
  (t) => [index("khr_user").on(t.userId), index("khr_expires").on(t.expiresAt)],
);

export const keyHandoffApprovals = sqliteTable(
  "key_handoff_approvals",
  {
    requestId: text("request_id")
      .notNull()
      .references(() => keyHandoffRequests.id, { onDelete: "cascade" }),
    source: text("source").notNull(),
    shareIndex: integer("share_index").notNull(),
    approverUserId: text("approver_user_id").$type<UserId>().notNull(),
    approverKeyFingerprintHex: text("approver_key_fingerprint_hex")
      .$type<KeyFingerprintHex>()
      .notNull(),
    encHex: text("enc_hex").notNull(),
    ciphertextHex: text("ciphertext_hex").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [primaryKey({ columns: [t.requestId, t.source, t.shareIndex] })],
);

export const keyWrapWindows = sqliteTable(
  "key_wrap_windows",
  {
    userId: text("user_id").$type<UserId>().notNull(),
    kind: text("kind").notNull(),
    windowStart: integer("window_start").notNull(),
    count: integer("count").notNull().default(0),
  },
  (t) => [primaryKey({ columns: [t.userId, t.kind] })],
);

export const projects = sqliteTable(
  "projects",
  {
    id: text("id").$type<ProjectId>().primaryKey(),
    orgId: text("org_id")
      .$type<OrgId>()
      .notNull()
      .references(() => organizations.id),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("proj_org").on(t.orgId)],
);

export const projectMembers = sqliteTable(
  "project_members",
  {
    projectId: text("project_id").$type<ProjectId>().notNull(),
    userId: text("user_id").$type<UserId>().notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.projectId, t.userId] }),
    index("pm_user_project").on(t.userId, t.projectId),
  ],
);

export const invitations = sqliteTable(
  "invitations",
  {
    id: text("id").primaryKey(),
    projectId: text("project_id").$type<ProjectId>().notNull(),
    linkPub: text("link_pub").notNull(),
    headHash: text("head_hash").notNull(),
    headSeq: integer("head_seq").notNull(),
    issueSignature: text("issue_signature").notNull(),
    role: text("role").notNull(),
    scopeKind: text("scope_kind").notNull(),
    scopeEnvironments: text("scope_environments").notNull(),
    inviterUserId: text("inviter_user_id").$type<UserId>().notNull(),
    status: text("status").notNull(),
    expiresAt: integer("expires_at").notNull(),
    inviteeUserId: text("invitee_user_id").$type<UserId>(),
    inviteeEncPub: text("invitee_enc_pub"),
    inviteeSigPub: text("invitee_sig_pub"),
    acceptSignature: text("accept_signature"),
    linkSignature: text("link_signature"),
    acceptedAt: integer("accepted_at"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [
    uniqueIndex("inv_link_pub").on(t.linkPub),
    index("inv_project_status").on(t.projectId, t.status),
    index("inv_project_created").on(t.projectId, t.createdAt),
  ],
);

const auditEventColumns = {
  seq: integer("seq").primaryKey({ autoIncrement: true }),
  rowId: text("row_id").notNull(),
  serverTs: integer("server_ts").notNull(),
  event: text("event").notNull(),
  actorType: text("actor_type").notNull(),
  actorUserId: text("actor_user_id").$type<UserId>(),
  actorApiTokenId: text("actor_api_token_id"),
  targetUserId: text("target_user_id").$type<UserId>(),
  orgId: text("org_id").$type<OrgId>(),
  projectId: text("project_id").$type<ProjectId>(),
  payload: text("payload"),
};

export const loginFailedWindows = sqliteTable("login_failed_windows", {
  bucket: text("bucket").primaryKey(),
  windowStart: integer("window_start").notNull(),
  recordedCount: integer("recorded_count").notNull().default(0),
  suppressedCount: integer("suppressed_count").notNull().default(0),
});

export const userAuditEvents = sqliteTable("user_audit_events", auditEventColumns, (t) => [
  uniqueIndex("uae_row_id").on(t.rowId),
  index("uae_actor").on(t.actorUserId, t.seq),
  index("uae_target").on(t.targetUserId, t.seq),
  index("uae_event").on(t.event, t.seq),
]);

export const orgAuditEvents = sqliteTable("org_audit_events", auditEventColumns, (t) => [
  uniqueIndex("oae_row_id").on(t.rowId),
  index("oae_actor").on(t.actorUserId, t.seq),
  index("oae_target").on(t.targetUserId, t.seq),
  index("oae_event").on(t.event, t.seq),
  index("oae_org").on(t.orgId, t.seq),
  index("oae_project").on(t.projectId, t.seq),
]);

export const opsCounters = sqliteTable(
  "ops_counters",
  {
    metric: text("metric").notNull(),
    windowStart: integer("window_start").notNull(),
    count: integer("count").notNull().default(0),
  },
  (t) => [primaryKey({ columns: [t.metric, t.windowStart] })],
);

export const opsBackups = sqliteTable("ops_backups", {
  projectId: text("project_id").$type<ProjectId>().primaryKey(),
  doIdHex: text("do_id_hex").notNull(),
  lastAttemptAt: integer("last_attempt_at").notNull(),
  lastSuccessAt: integer("last_success_at"),
  lastObjectKey: text("last_object_key"),
  lastBytes: integer("last_bytes"),
  lastAuditSeq: integer("last_audit_seq"),
  lastChainSeq: integer("last_chain_seq"),
  lastAttestationMark: integer("last_attestation_mark"),
  storageLevel: text("storage_level"),
  consecutiveFailures: integer("consecutive_failures").notNull().default(0),
  lastFailureCode: text("last_failure_code"),
});

export const opsState = sqliteTable("ops_state", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
  updatedAt: integer("updated_at").notNull(),
});
