// The D1 schema of AUTH_SPEC §2 (Drizzle; ADR-0006).
//
// Drizzle types never leave this boundary (db.package): table definitions
// and select-result types are for the repository services' implementation
// only; the public API is domain types and Effect types only (see
// index.ts).
//
// Rules (AUTH_SPEC §2):
// - Every reference from any other structure goes through users.id (the
//   internal ULID) only. provider_user_id must not be used as a foreign key
// - Lookups happen only on (provider, provider_user_id). Build no lookup by
//   email
// - memberships.role (the org role) does not participate in project access
//   (§9-2)
// - projects is org-belonging metadata, not the source of truth of
//   in-project permissions (the source of truth is the membership chain —
//   the ban on two sources of truth, CRYPTO_SPEC §6.4)
//
// All times are INTEGER unix ms.
//
// The identity columns carry the branded domain types (`$type<UserId>()` /
// `$type<ProviderUserId>()`): mapping a row is the repository service's
// trust boundary, so a selected value arrives already minted and a
// `.values()` insert refuses a plain string. Drizzle does not type-check the
// columns of an INSERT…SELECT: the audit insert-selects take their user ids
// from `guardedAuditSelectColumns` (typed input) or from a branded column.
// Branded: users.id and the user_id columns of the
// auth plumbing (linked_identities / sessions / api_tokens /
// cli_login_flows), the provider_user_id lookup key, the audit log's
// actor / target, and the columns an audit target or a chain entry is
// read from (an invitation's invitee — the add_member target; a guardian
// group's ward and guardians; a handoff request's ward).

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
  /** The internal user_id (ULID). The principal identifier across the whole system */
  id: text("id").$type<UserId>().primaryKey(),
  /** For display and notifications. Must not be used as an identifier. Only GitHub-verified ones are stored */
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
    /** 'github' (future: 'workos' etc.) */
    provider: text("provider").notNull(),
    /** GitHub's numeric ID as a string (not the login name — a login can change) */
    providerUserId: text("provider_user_id").$type<ProviderUserId>().notNull(),
    /** Display snapshot */
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
    // Future columns (not created now): sso_connection_id, allowed_domains, enforce_sso
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
    /** The org role: 'owner' | 'admin' | 'member' (does not participate in project access) */
    role: text("role").notNull(),
  },
  (t) => [primaryKey({ columns: [t.orgId, t.userId] }), index("mem_user").on(t.userId)],
);

export const sessions = sqliteTable(
  "sessions",
  {
    /** SHA-256 (hex) of the random 256-bit session value. The raw value is never stored */
    id: text("id").primaryKey(),
    userId: text("user_id")
      .$type<UserId>()
      .notNull()
      .references(() => users.id),
    /** An auth-method kind name (core AUTH_METHODS — only issueSession writes it). Needed for the SSO-enforcement policy */
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
    /** SHA-256 (hex). The raw token is returned only once at issuance */
    tokenHash: text("token_hash").notNull(),
    /** For display (e.g. maruhi_pat_Ab12…) */
    tokenPrefix: text("token_prefix").notNull(),
    /** A JSON array of TokenScope (the scope representation of AUTH_SPEC §6) */
    scopes: text("scopes").notNull(),
    expiresAt: integer("expires_at").notNull(),
    createdAt: integer("created_at").notNull(),
    lastUsedAt: integer("last_used_at"),
  },
  (t) => [
    uniqueIndex("tok_hash").on(t.tokenHash),
    index("tok_user").on(t.userId),
    // A same-named token is a rotation (AUTH_SPEC §6). One row guaranteed by a DB constraint even under concurrent issuance
    uniqueIndex("tok_user_name").on(t.userId, t.name),
  ],
);

/**
 * Per-deployment server settings (AUTH_SPEC §3). The only key today is
 * `signup_policy` ('open' | 'invite' | 'closed'; no row = 'open').
 * No write path exists in code — changes go through the operator's cf
 * / SQL path only (docs/SELF_HOSTING.md; no admin UI or settings API will
 * be built). Readers treat an unknown value as 'closed' (fail-closed —
 * readSignupPolicy in identities.ts).
 */
export const deploymentSettings = sqliteTable("deployment_settings", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
  updatedAt: integer("updated_at").notNull(),
});

/**
 * Signup invite codes (AUTH_SPEC §3). Only the SHA-256 hash of a 256-bit
 * random bearer (`maruhi_sgn_` + Base62) is stored; single-use (consumption
 * CAS); expires (following the §15 invitations shape). A code carries only
 * permission to create an account — it is not bound to a project, org,
 * role, or provider identifier.
 *
 * - Issuance is an operator operation (scripts/issue-signup-invite.ts +
 *   cf d1) — the server has no issuance path
 * - Consumption (status 'pending' → 'used') is a CAS inside the same D1
 *   batch as the account creation (identities.ts — eliminates both "creation
 *   failed but the code burned" and "creation succeeded but the code
 *   survives")
 * - No FK on used_by_user_id: the consumption UPDATE runs **before** the
 *   users row insert in the same batch (the creation side reads the CAS's
 *   changes()), so referential integrity is structurally impossible (the
 *   same "no FK" decision as invitations)
 */
export const signupInvites = sqliteTable(
  "signup_invites",
  {
    /** ULID (issued by the issuance script). Same value as the audit payload's signupInviteId */
    id: text("id").primaryKey(),
    /** SHA-256 (hex) of the whole presented string (maruhi_sgn_…). The raw value exists only at issuance */
    tokenHash: text("token_hash").notNull(),
    /** 'pending' | 'used' (expiry is derived from expires_at — same as §15) */
    status: text("status").notNull(),
    /** Issued + 7 days (drafting value — the issuance script computes it) */
    expiresAt: integer("expires_at").notNull(),
    createdAt: integer("created_at").notNull(),
    usedByUserId: text("used_by_user_id").$type<UserId>(),
    usedAt: integer("used_at"),
  },
  (t) => [uniqueIndex("sgn_token_hash").on(t.tokenHash)],
);

/**
 * The flow signing key (AUTH_SPEC §4-2). The HMAC-SHA-256 key that verifies
 * a CLI login's flowToken / vsig; auto-generated and stored on first use
 * (idempotent — first-to-insert wins + read back). It is credential
 * protection of the auth layer and outside CRYPTO_SPEC's scope (no E2EE
 * property relies on it). At most one row under a fixed id.
 */
export const flowSigningKeys = sqliteTable("flow_signing_keys", {
  /** A fixed identifier (currently only one row, 'v1') */
  id: text("id").primaryKey(),
  /** The HMAC-SHA-256 key (256-bit, 64 lowercase hex chars) */
  keyHex: text("key_hex").notNull(),
  createdAt: integer("created_at").notNull(),
});

/**
 * A CLI login flow row (AUTH_SPEC §4-1 (4) (iii)). start is unrecorded
 * (ruling DH); a row is born **for the first time** at the callback's
 * create-or-match CAS — at birth the authenticated user_id, the issuance
 * parameters (from the vsig'd URL), the expiry, and the approval ticket
 * are all fixed (no intermediate state exists).
 *
 * - status: 'awaiting' | 'approved' | 'denied' | 'consumed'. Approve /
 *   deny is a CAS from awaiting; PAT issuance is only for the winner of
 *   the approved → consumed CAS (§4-1 (5))
 * - ticket_hash: SHA-256 (hex) of the approval ticket (256-bit random).
 *   The raw value is embedded only in the page; always the latest one
 *   (replaced when the same user_id arrives again)
 * - consumed / denied rows are not deleted until expiry + slack (deleting
 *   earlier would make poll misread "no row = pending" — §4-1 (5)).
 *   Cleanup is only an opportunistic delete after expiry
 */
export const cliLoginFlows = sqliteTable(
  "cli_login_flows",
  {
    /** The public correlator flowId (128-bit random, 32 lowercase hex chars) */
    id: text("id").primaryKey(),
    userId: text("user_id")
      .$type<UserId>()
      .notNull()
      .references(() => users.id),
    status: text("status").notNull(),
    /** Issuance parameter (its default resolved at start — a final value the vsig covers) */
    tokenName: text("token_name").notNull(),
    /** A JSON array of TokenScope (same representation as api_tokens.scopes) */
    scopes: text("scopes").notNull(),
    expiresInDays: integer("expires_in_days").notNull(),
    /** A short display code for comparison (not a secret — §4-1 (2)) */
    userCode: text("user_code").notNull(),
    /** SHA-256 (hex) of the approval ticket (raw 256-bit random). */
    ticketHash: text("ticket_hash").notNull(),
    /** The flow's expiry (unix ms — same value as the signed expiry of flowToken / vsig) */
    expiresAt: integer("expires_at").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  // For the opportunistic delete (sweeping rows past expiry + slack)
  (t) => [index("clf_expires").on(t.expiresAt)],
);

export const recoveryWraps = sqliteTable("recovery_wraps", {
  /** At most one per user (AUTH_SPEC §13-1) */
  userId: text("user_id")
    .$type<UserId>()
    .primaryKey()
    .references(() => users.id),
  /** The suite identifier (CRYPTO_SPEC §2 design principle 4) */
  suite: text("suite").notNull(),
  /** A 96-bit nonce (24 lowercase hex chars) */
  nonceHex: text("nonce_hex").notNull(),
  /** AES-256-GCM ct || tag (lowercase hex). The server never decrypts or interprets it */
  ciphertextHex: text("ciphertext_hex").notNull(),
  createdAt: integer("created_at").notNull(),
  updatedAt: integer("updated_at").notNull(),
});

// ---------------------------------------------------------------------------
// The master-key wrap ledger (AUTH_SPEC §13-6 — KL3. Classes S / G / H of
// CRYPTO_SPEC §8). All per-user; a wrap or a segment is an opaque
// ciphertext as far as the server is concerned.
// ---------------------------------------------------------------------------

/** Class S's new path (passkey-prf). recovery-code stays on recovery_wraps. */
export const masterKeyWraps = sqliteTable(
  "master_key_wraps",
  {
    /** wrap_id (ULID) */
    id: text("id").primaryKey(),
    userId: text("user_id")
      .$type<UserId>()
      .notNull()
      .references(() => users.id),
    /** 'passkey-prf' */
    kind: text("kind").notNull(),
    suite: text("suite").notNull(),
    /** JSON (public parameters: credentialIdHex / prfSaltHex / rpId / label). The server does not interpret it */
    params: text("params").notNull(),
    nonceHex: text("nonce_hex").notNull(),
    ciphertextHex: text("ciphertext_hex").notNull(),
    createdAt: integer("created_at").notNull(),
    updatedAt: integer("updated_at").notNull(),
  },
  (t) => [index("mkw_user").on(t.userId)],
);

/** Class G: guardian groups (a wrap of B under the group KEK). */
export const guardianGroups = sqliteTable(
  "guardian_groups",
  {
    /** group_id (ULID) */
    id: text("id").primaryKey(),
    /** ward */
    userId: text("user_id")
      .$type<UserId>()
      .notNull()
      .references(() => users.id),
    /** 'any' | 'all' */
    mode: text("mode").notNull(),
    suite: text("suite").notNull(),
    nonceHex: text("nonce_hex").notNull(),
    ciphertextHex: text("ciphertext_hex").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("gg_user").on(t.userId)],
);

/**
 * Class G: a segment (an HPKE Seal to the guardian's enc public key).
 * **One row per guardian device** (2026-09-19 DK — AUTH_SPEC §13-6: the
 * same logical segment share_index is sealed to each of the guardian's
 * valid device keys. info contains no device, but the recipient keys
 * differ so they cannot open each other's — CRYPTO_SPEC §8.3).
 * The primary key is (group_id, share_index,
 * guardian_key_fingerprint_hex); one row (UNIQUE) per same-guardian
 * same-device. The uniqueness of a logical segment (share_index ↔
 * guardian) is checked at the acceptance stage (handlers-key-wraps.ts)
 * (design record dk-design.md §8 K3-10).
 */
export const guardianShares = sqliteTable(
  "guardian_shares",
  {
    groupId: text("group_id")
      .notNull()
      .references(() => guardianGroups.id, { onDelete: "cascade" }),
    /** 1..n (a logical segment — one per guardian) */
    shareIndex: integer("share_index").notNull(),
    guardianUserId: text("guardian_user_id")
      .$type<UserId>()
      .notNull()
      .references(() => users.id),
    /** The seal target (a key the ward client has confirmed) */
    guardianEncPubHex: text("guardian_enc_pub_hex").notNull(),
    /** The seal target's device key FP (one row per guardian device — DK) */
    guardianKeyFingerprintHex: text("guardian_key_fingerprint_hex").$type<KeyFingerprintHex>().notNull(),
    encHex: text("enc_hex").notNull(),
    /** A 32-byte segment + a 16-byte tag = 48 bytes */
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

/**
 * The device registry (AUTH_SPEC §13-11 — 2026-09-19 DK. **Advisory**: a
 * store of display names, token associations, and public keys; never an
 * input to any verification or authorization. The source of truth is each
 * project's chain's `add_device` / `revoke_device`). Up to 32 rows per
 * user (acceptance policy). Carries no audit events (the same discipline
 * as the §6 token list).
 */
/**
 * The columns shared by the device registry and device-add requests:
 * owner + device key FP (CRYPTO_SPEC §3 — the first 16 bytes of SHA-256
 * of enc ‖ sig; recomputed from the body's public keys and matched) +
 * public keys + a display name (the same acceptance discipline as the §6
 * token name — no control characters, no bidi, ≤128 chars).
 */
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
    /** Optional: this device's API token id (§6 — advisory; never an input to authorization) */
    tokenId: text("token_id"),
  },
  (t) => [primaryKey({ columns: [t.userId, t.keyFingerprintHex] })],
);

/**
 * A device-add request (AUTH_SPEC §13-11): a request row that hands the
 * new device's public key to an approving device (TTL 15 minutes). No
 * state column (a row = an unconsumed request; after approval the client
 * deletes it, and an expired row is deleted opportunistically — design
 * record §8 K3-8). The approving client recomputes the FP from the
 * response's public keys and ignores anything that does not match the FP
 * a human carried (server-side public-key substitution is caught by the
 * FP comparison).
 */
export const deviceAddRequests = sqliteTable(
  "device_add_requests",
  {
    ...deviceKeyColumns(),
    expiresAt: integer("expires_at").notNull(),
  },
  (t) => [primaryKey({ columns: [t.userId, t.keyFingerprintHex] })],
);

/** Class H: a handoff request (E.pub is not stored — request_id is its derived value). */
export const keyHandoffRequests = sqliteTable(
  "key_handoff_requests",
  {
    /** request_id (CRYPTO_SPEC §8.4 — SHA-256 hex) */
    id: text("id").primaryKey(),
    /** The ward (the requester) */
    userId: text("user_id")
      .$type<UserId>()
      .notNull()
      .references(() => users.id),
    createdAt: integer("created_at").notNull(),
    /** Issued + 15 minutes */
    expiresAt: integer("expires_at").notNull(),
    /** When the requester first obtained at least one approval (auth.key_handoff_collected is recorded exactly once) */
    collectedAt: integer("collected_at"),
  },
  (t) => [index("khr_user").on(t.userId), index("khr_expires").on(t.expiresAt)],
);

/** Class H: an approval (a response scope that dies with its request). */
export const keyHandoffApprovals = sqliteTable(
  "key_handoff_approvals",
  {
    requestId: text("request_id")
      .notNull()
      .references(() => keyHandoffRequests.id, { onDelete: "cascade" }),
    /** group_id (a guardian group. The old device-path 'device' was removed in 2026-09-19 DK K4) */
    source: text("source").notNull(),
    shareIndex: integer("share_index").notNull(),
    approverUserId: text("approver_user_id").$type<UserId>().notNull(),
    approverKeyFingerprintHex: text("approver_key_fingerprint_hex").$type<KeyFingerprintHex>().notNull(),
    encHex: text("enc_hex").notNull(),
    ciphertextHex: text("ciphertext_hex").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [primaryKey({ columns: [t.requestId, t.source, t.shareIndex] })],
);

/**
 * The §13-8 fixed windows (mutable state, not an audit row — same
 * character as login_failed_windows). kind = 'blob-fetch' (the summed
 * kinds of blob fetches — includes recovery-code) / 'handoff-request' /
 * 'approval'.
 */
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
    /** Project ID = genesis entry hash (64 lowercase hex chars; CRYPTO_SPEC §6.4) */
    id: text("id").$type<ProjectId>().primaryKey(),
    /** Org belonging (AUTH_SPEC §11-3. NOT NULL = a project without an org does not exist) */
    orgId: text("org_id")
      .$type<OrgId>()
      .notNull()
      .references(() => organizations.id),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("proj_org").on(t.orgId)],
);

/**
 * The D1 projection of chain-derived membership (AUTH_SPEC §11-5).
 *
 * **A candidate index for discovery only**; never used for any
 * authorization decision (the source of truth of project access is the
 * membership chain — the "ban on two sources of truth" of CRYPTO_SPEC
 * §6.4. The listing response contains only rows that passed each project
 * DO's membership confirmation at read time; a stale row is deleted at
 * read time and converges). Intentionally carries no role or state
 * column: the role uses the current value the read-time confirmation
 * returns, so projection-following of change_role is structurally
 * unnecessary (session-42 ruling BI, second pass).
 *
 * No FKs (same reason as invitations: a derived cache must not impede
 * acceptance or repair via referential integrity — and must not
 * interfere with the §11-3 partial-failure window).
 */
export const projectMembers = sqliteTable(
  "project_members",
  {
    /** The genesis hash (64 lowercase hex chars) */
    projectId: text("project_id").$type<ProjectId>().notNull(),
    /** The internal user_id (ULID) */
    userId: text("user_id").$type<UserId>().notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.projectId, t.userId] }),
    // Candidate enumeration for the listing (cursor paging on the user
    // axis, ascending project_id — §11-5)
    index("pm_user_project").on(t.userId, t.projectId),
  ],
);

export const invitations = sqliteTable(
  "invitations",
  {
    /** ULID */
    id: text("id").primaryKey(),
    /**
     * The genesis hash (AUTH_SPEC §15-1). No FK to projects: an invite is
     * authorized by the chain (DO)'s role, and the projects row is only
     * org-belonging metadata (an invite may well come into being while a
     * §11-3 partial-failure repair is in progress)
     */
    projectId: text("project_id").$type<ProjectId>().notNull(),
    /**
     * The link public key (Ed25519, 64 lowercase hex chars — CRYPTO_SPEC
     * §6.5). The client generates and declares it at issuance. The
     * acceptance resolution key (UNIQUE)
     */
    linkPub: text("link_pub").notNull(),
    /** Issuance statement: the inviter's verified head at issuance (64 hex chars) and seq. A public value */
    headHash: text("head_hash").notNull(),
    headSeq: integer("head_seq").notNull(),
    /** The issuance signature (the inviter's chain sig key, 128 hex chars). The server stores and serves it without verifying */
    issueSignature: text("issue_signature").notNull(),
    /** 'reader' | 'member' | 'admin' (owner is never granted via an invite — §15-1) */
    role: text("role").notNull(),
    /** The kind of the scope to be granted ('all' | 'listed' — AUTH_SPEC §15-2, 2026-09-14 ES) */
    scopeKind: text("scope_kind").notNull(),
    /**
     * The list of environment_ids of the scope to be granted (a JSON
     * array as a string; `[]` for `all`). Part of the issuance statement
     * (covered by the issuance signature); the server stores and serves
     * it without verifying
     */
    scopeEnvironments: text("scope_environments").notNull(),
    inviterUserId: text("inviter_user_id").$type<UserId>().notNull(),
    /** 'pending' | 'accepted' | 'completed' | 'revoked' (expiry is derived from expires_at) */
    status: text("status").notNull(),
    /** Issued + 7 days (§15-1 drafting value) */
    expiresAt: integer("expires_at").notNull(),
    // The acceptance block (status is accepted-or-later — §15-1)
    inviteeUserId: text("invitee_user_id").$type<UserId>(),
    inviteeEncPub: text("invitee_enc_pub"),
    inviteeSigPub: text("invitee_sig_pub"),
    /** The acceptance signature of CRYPTO_SPEC §6.5 (hex). Input for the inviter client's independent verification */
    acceptSignature: text("accept_signature"),
    /** The link signature of CRYPTO_SPEC §6.5 (hex). The link key's joint signature over the same byte string */
    linkSignature: text("link_signature"),
    acceptedAt: integer("accepted_at"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [
    // The acceptance resolution key (§15-2)
    uniqueIndex("inv_link_pub").on(t.linkPub),
    // The pending cap (the status condition) and the listing
    index("inv_project_status").on(t.projectId, t.status),
    // The issuance fixed-window rate limit (the created_at range)
    index("inv_project_created").on(t.projectId, t.createdAt),
  ],
);

// ---------------------------------------------------------------------------
// The D1-side audit events (AUDIT_SPEC §3.1-§3.2; the storage ruling is
// §5.2 option A)
//
// - The column layout is the same design as the project DO's
//   audit_events (§5.1) (frequent attributes promoted to columns + a
//   payload JSON). It does not carry the DO-only columns (chain and
//   variable coordinates, key FPs) because they never appear on D1-side
//   events; org_id / project_id are promoted for org-family cross queries
// - seq is autoincrement (§5.2. There is no DO gapless guarantee —
//   practically sufficient in D1)
// - append-only (§1-4): write no code that issues UPDATE / DELETE against
//   this table. The read API is designed together with the Phase 2 audit
//   log UI (§6)
// - No FK to users: an audit row outlives the row it records, and
//   referential integrity must not impede the append (fail toward keeping
//   §1-4's append-only)
// ---------------------------------------------------------------------------

/** The common columns of the user / org audit tables (Drizzle's shared-column-object pattern). */
const auditEventColumns = {
  seq: integer("seq").primaryKey({ autoIncrement: true }),
  /** The wire row identifier (16-byte random hex — AUDIT_SPEC §5.1 / §7. seq never goes on the wire) */
  rowId: text("row_id").notNull(),
  /** The server's acceptance time (unix ms) */
  serverTs: integer("server_ts").notNull(),
  /** The AUDIT_SPEC §3 event name (`domain.verb`) */
  event: text("event").notNull(),
  /** The §2 actor kind. On the D1 side, currently only 'user' (login_failed is a user with no user_id) */
  actorType: text("actor_type").notNull(),
  actorUserId: text("actor_user_id").$type<UserId>(),
  actorApiTokenId: text("actor_api_token_id"),
  /** The target of a member operation */
  targetUserId: text("target_user_id").$type<UserId>(),
  orgId: text("org_id").$type<OrgId>(),
  projectId: text("project_id").$type<ProjectId>(),
  /** JSON. Supplements such as auth_method and snapshots. Contains nothing §1-2/1-3 forbids */
  payload: text("payload"),
};

/**
 * The recording-window counter for `auth.login_failed` (AUDIT_SPEC §3.1).
 *
 * A mutable counter state, not an audit row (the §1-4 append-only is the
 * audit tables' discipline). If the in-window count were computed by
 * scanning the audit log, every unauthenticated-path append would scan an
 * ever-growing append-only table — the very flood we want to bound would
 * become a cost amplifier.
 *
 * Row granularity = bucket (currently `auth_method`). Carries **no
 * source identifier** (the §1-2 line — the reason for not counting per
 * source is §3.1).
 */
export const loginFailedWindows = sqliteTable("login_failed_windows", {
  /** The counting bucket. Currently an auth_method kind name (github_oauth / cli_handoff) */
  bucket: text("bucket").primaryKey(),
  /** The fixed window's start (unix ms) */
  windowStart: integer("window_start").notNull(),
  /** Count recorded as audit rows in this window (up to the cap) */
  recordedCount: integer("recorded_count").notNull().default(0),
  /** Count dropped by the cap in this window (the basis of the suppression marker) */
  suppressedCount: integer("suppressed_count").notNull().default(0),
});

/** The auth-family events (AUDIT_SPEC §3.1). */
export const userAuditEvents = sqliteTable("user_audit_events", auditEventColumns, (t) => [
  uniqueIndex("uae_row_id").on(t.rowId),
  index("uae_actor").on(t.actorUserId, t.seq),
  index("uae_target").on(t.targetUserId, t.seq),
  index("uae_event").on(t.event, t.seq),
]);

/** The org-family events (AUDIT_SPEC §3.2). */
export const orgAuditEvents = sqliteTable("org_audit_events", auditEventColumns, (t) => [
  uniqueIndex("oae_row_id").on(t.rowId),
  index("oae_actor").on(t.actorUserId, t.seq),
  index("oae_target").on(t.targetUserId, t.seq),
  index("oae_event").on(t.event, t.seq),
  index("oae_org").on(t.orgId, t.seq),
  // For paging the project_id-scoped read of invite.* (AUDIT_SPEC §7)
  index("oae_project").on(t.projectId, t.seq),
]);

// ---------------------------------------------------------------------------
// Operations (docs/notes/hosted-ops.md §6). **Operator-only mutable
// state**, not an audit log (hosted-design.md §5-5 — never mix audit and
// ops logs). None of the tables carries any request-derived identifier
// other than the project ID (ops_backups' project_id is a reference
// inside the same operator store as the `projects` table and is never
// placed on an evacuation object's key).
// ---------------------------------------------------------------------------

/**
 * Ops counters (fixed windows — hosted-ops.md §2-A). metric =
 * `github_token_requests` (our own counting of GitHub token requests) /
 * `cli_flow_capacity` (the login-flow row creation cap reached). The
 * window is one hour; rows older than 7 days are deleted at evaluation
 * time (bounded).
 */
export const opsCounters = sqliteTable(
  "ops_counters",
  {
    metric: text("metric").notNull(),
    /** The fixed window's start (unix ms, on an hour boundary) */
    windowStart: integer("window_start").notNull(),
    count: integer("count").notNull().default(0),
  },
  (t) => [primaryKey({ columns: [t.metric, t.windowStart] })],
);

/**
 * The record of DO → R2 evacuations (hosted-ops.md §4-2). One row per
 * project. do_id_hex is the (one-way) image of `idFromName(projectId)`
 * and is kept to cross-check against the R2 key. storage_level is the
 * census at evacuation time (the §12-8 judgment of AUTH_SPEC — admit /
 * warn / reject).
 */
export const opsBackups = sqliteTable("ops_backups", {
  projectId: text("project_id").$type<ProjectId>().primaryKey(),
  doIdHex: text("do_id_hex").notNull(),
  lastAttemptAt: integer("last_attempt_at").notNull(),
  lastSuccessAt: integer("last_success_at"),
  lastObjectKey: text("last_object_key"),
  lastBytes: integer("last_bytes"),
  lastAuditSeq: integer("last_audit_seq"),
  lastChainSeq: integer("last_chain_seq"),
  /** The latest acceptance time of a head attestation (the skip rule's third component — do-snapshot.ts readWatermarks) */
  lastAttestationMark: integer("last_attestation_mark"),
  storageLevel: text("storage_level"),
  consecutiveFailures: integer("consecutive_failures").notNull().default(0),
  /** A static failure code only (never an error message body) */
  lastFailureCode: text("last_failure_code"),
});

/** A small ops-state kv (sweep cursors, alert states — JSON strings). */
export const opsState = sqliteTable("ops_state", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
  updatedAt: integer("updated_at").notNull(),
});
