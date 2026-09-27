// The Effect service implementation of the D1 repositories (AUTH_SPEC
// §2; ADR-0006).
//
// - Drizzle types and queries are confined to this file (inside the
//   db.package boundary). The public shapes are domain types
//   (../auth-domain.ts) and Effect only
// - A D1 failure (connection, SQL error) is treated as a defect
//   (Effect.promise). Only the domain-expected branches (no such row,
//   a unique-constraint conflict) are expressed as values
// - The settled decision to adopt Drizzle is session 06: classic
//   drizzle-orm/d1 was adopted. The effect-d1 driver at rc.4 did not
//   support transaction / batch, so getOrCreateUser (§1-5), which needs
//   atomicity, could not stand. D1's atomic batch is used

import type { SignupPolicy } from "@maruhi/api-schema";
import type { OrgRole, TokenScope } from "@maruhi/core";
import { parseTokenScopes } from "@maruhi/core";
import { and, count, eq, gt, gte, inArray, isNull, lte, min, or, sql, type SQL } from "drizzle-orm";
import { drizzle } from "drizzle-orm/d1";
import { Context, Data, Effect } from "effect";

import type {
  ApiTokenRecord,
  ApiTokenSummary,
  RecoveryFetchDecision,
  RecoveryWrapRecord,
  ResolvedUser,
  SessionRecord,
  SignupGateResult,
  UserOrg,
  VerifiedIdentity,
} from "../auth-domain.ts";
import { ulid } from "../ids.ts";
import type {
  InvitationRecord,
  InviteScope,
  InviteAcceptInput,
  InviteCompletionTarget,
  InviteIssuance,
  InviteIssueDecision,
  InviteRole,
  InviteStatus,
} from "../invite-domain.ts";
import type { D1AuditActor } from "./audit.ts";
import {
  D1AuditRepo,
  guardedAuditSelectColumns,
  makeD1AuditRepo,
  orgAuditInsert,
  userAuditInsert,
} from "./audit.ts";
import { DeviceRepo, makeDeviceRepo } from "./devices.ts";
import {
  KEY_BLOB_FETCH_LIMIT,
  KeyWrapRepo,
  type KeyWrapRepoShape,
  makeKeyWrapRepo,
} from "./key-wraps.ts";
import { makeOpsRepo, OpsRepo } from "./ops.ts";
import {
  apiTokens,
  cliLoginFlows,
  deploymentSettings,
  flowSigningKeys,
  invitations,
  keyWrapWindows,
  linkedIdentities,
  memberships,
  organizations,
  orgAuditEvents,
  projectMembers,
  projects,
  recoveryWraps,
  sessions,
  signupInvites,
  userAuditEvents,
  users,
} from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

const run = <T>(evaluate: () => Promise<T>): Effect.Effect<T> => Effect.promise(evaluate);

// ---------------------------------------------------------------------------
// IdentityRepo (§1-5 getOrCreateUser / §9-1 automatic personal-org
// creation)
// ---------------------------------------------------------------------------

interface IdentityRepoShape {
  /**
   * The single idempotent entry point. On fresh creation, a personal
   * org owned by the user is created at the same time.
   *
   * The signupPolicy gate (AUTH_SPEC §3) sits right before the "absent →
   * create" branch and never affects resolving an existing user.
   * `signupInviteTokenHash` is the SHA-256 of the signup invite code
   * (the whole presented string; null when not presented). A creation
   * under `invite` happens in the same D1 batch as the code-consumption
   * CAS.
   */
  readonly getOrCreateUser: (
    identity: VerifiedIdentity,
    nowMs: number,
    signupInviteTokenHash: string | null,
  ) => Effect.Effect<SignupGateResult>;
  /**
   * Lookup only (never creates — AUTH_SPEC §4-1 (4) (ii), ruling DH).
   * Used by the browser leg of CLI login: a missing account ends in
   * signup guidance and produces no irreversible side effect.
   */
  readonly lookupUser: (identity: VerifiedIdentity) => Effect.Effect<string | null>;
  /** The orgs the user belongs to (for discovering where to create a project. §11-3). */
  readonly listUserOrgs: (userId: string) => Effect.Effect<readonly UserOrg[]>;
  /**
   * The GitHub display login snapshot (`/auth/me`'s providerLogin — the
   * input of AUTH_SPEC §15-3's `il`). null when unlinked or unstored.
   */
  readonly providerLoginOf: (userId: string) => Effect.Effect<string | null>;
  /**
   * The signupPolicy at acceptance time (AUTH_SPEC §3). No row = 'open'
   * (the default = legacy behavior); an unknown stored value = 'closed'
   * (fail-closed — an operator's misconfiguration never silently turns
   * into 'open'). Read by `/auth/config`'s advisory and by the wording
   * branch of the CLI signup-guidance page.
   */
  readonly signupPolicy: Effect.Effect<SignupPolicy>;
  /**
   * Pre-validation of a signup invite code (AUTH_SPEC §3 — fail-fast at
   * the start of `start`). True only when it exists, is unconsumed, and
   * is unexpired. A 256-bit single-use random, so it is not an
   * existence oracle (same level as the §15 invite tokens). Not
   * consumed here (consumption happens only in the CAS inside
   * getOrCreateUser's creation batch).
   */
  readonly hasPendingSignupInvite: (tokenHashHex: string, nowMs: number) => Effect.Effect<boolean>;
}

export class IdentityRepo extends Context.Service<IdentityRepo, IdentityRepoShape>()(
  "IdentityRepo",
) {}

function lookupLinkedUser(db: Db, identity: VerifiedIdentity): Effect.Effect<string | null> {
  return run(async () => {
    const row = await db
      .select({ userId: linkedIdentities.userId })
      .from(linkedIdentities)
      .where(
        and(
          eq(linkedIdentities.provider, identity.provider),
          eq(linkedIdentities.providerUserId, identity.providerUserId),
        ),
      )
      .get();
    return row === undefined ? null : row.userId;
  });
}

class InsertConflictError extends Data.TaggedError("InsertConflict")<object> {}

/**
 * Judges from the D1 error message whether a failure is a unique
 * constraint violation. Distinguished because misclassifying a
 * non-conflict failure (a transient outage, an FK violation, etc.) as a
 * "conflict" would make the re-lookup come up empty and misdirect the
 * incident investigation with a defect message that does not match
 * reality. drizzle wraps the error into `cause` depending on the path
 * (a batch passes it through; a single query wraps it in
 * DrizzleQueryError), so the cause chain is walked too. Exposed for
 * tests.
 */
export function isUniqueConflict(error: unknown): boolean {
  for (let current = error; current instanceof Error; current = current.cause) {
    if (current.message.includes("UNIQUE constraint failed")) {
      return true;
    }
  }
  return false;
}

/** The signupPolicy key in deployment_settings (AUTH_SPEC §3). */
const SIGNUP_POLICY_KEY = "signup_policy";

// The fail-closed warning for an unknown stored value is emitted once
// per isolate (/auth/config is a surface the synthetic monitor hits
// periodically — hosted-design.md §5-2 — and warning every time would
// flood the log). The message is static (the stored value itself is
// never written — the §11-5 discipline)
let warnedUnknownSignupPolicy = false;

/**
 * Read the signupPolicy at acceptance time (AUTH_SPEC §3). No row =
 * 'open'; an unknown value = 'closed' (fail-closed).
 */
async function readSignupPolicy(db: Db): Promise<SignupPolicy> {
  const row = await db
    .select({ value: deploymentSettings.value })
    .from(deploymentSettings)
    .where(eq(deploymentSettings.key, SIGNUP_POLICY_KEY))
    .get();
  if (row === undefined) {
    return "open";
  }
  if (row.value === "open" || row.value === "invite" || row.value === "closed") {
    return row.value;
  }
  if (!warnedUnknownSignupPolicy) {
    warnedUnknownSignupPolicy = true;
    console.warn(
      "deployment_settings.signup_policy has an unknown value; treating it as 'closed' (fail-closed — fix it with the SQL in docs/SELF_HOSTING.md)",
    );
  }
  return "closed";
}

/**
 * The signupPolicy condition evaluated inside the creation batch
 * (AUTH_SPEC §3 — "the judgment uses the setting at acceptance time").
 * Even if the setting transitions between the read (readSignupPolicy)
 * and the creation, the creation takes effect only when this condition
 * is true inside the batch's transaction — no race window against the
 * transition (the D1 shape equivalent to the §12-11 DO
 * serialization). The default 'open' of a missing row is folded by
 * coalesce.
 */
function signupPolicyIs(value: SignupPolicy): SQL {
  return sql`(select coalesce((select ${deploymentSettings.value} from ${deploymentSettings} where ${deploymentSettings.key} = ${SIGNUP_POLICY_KEY}), 'open')) = ${value}`;
}

/** The specification of the creation gate (AUTH_SPEC §3): open's policy condition or invite's consumption CAS. */
type SignupGate =
  | { readonly kind: "open" }
  | { readonly kind: "invite"; readonly inviteId: string };

/** A lost gate (a policy transition or a concurrent invite-code consumption). The caller re-judges. */
class SignupGateLostError extends Data.TaggedError("SignupGateLost")<object> {}

/**
 * Creates users + linked_identities + the personal org + the owner
 * membership in one atomic batch. Of two concurrent signups one fails
 * on the (provider, provider_user_id) PK, so on a conflict the caller
 * re-looks-up. A failure other than a conflict is a defect.
 *
 * The signupPolicy gate (AUTH_SPEC §3) is folded in as the batch's
 * head condition: for open it is the policy condition on the head
 * INSERT's WHERE; for invite it is the head consumption CAS (an UPDATE
 * that takes effect only on pending + unexpired + policy 'invite').
 * Every following statement chains on the previous one's success via
 * `changes() = 1` (the same D1 batch idiom as tokenInsertSelect), so a
 * batch whose gate lost is committed **having written nothing**
 * (neither the "burns a code only" shape nor a partial creation can
 * exist structurally).
 *
 * Audit (AUDIT_SPEC §3.1–§3.2) is appended in the same batch too:
 * auth.user_created (an invite-consumption origin carries signupInviteId
 * in the payload — AUDIT_SPEC §3.1) / auth.identity_linked (the
 * provider kind only — the numeric ID and login are never recorded) /
 * org.created (automatic personal-org creation; the org name derives
 * from providerLogin so it is not copied into the payload — §1-2) /
 * org.member_added (the owner themselves).
 */
function createUserBatch(
  db: Db,
  identity: VerifiedIdentity,
  nowMs: number,
  gate: SignupGate,
): Effect.Effect<string, InsertConflictError | SignupGateLostError> {
  const userId = ulid(nowMs);
  const orgId = ulid(nowMs);
  const actor: D1AuditActor = { userId };
  const chained = sql`changes() = 1`;
  // Every following statement is an INSERT…SELECT chained on the
  // previous one's success (changes() = 1) (the same shape as
  // tokenInsertSelect). Every inserted row is a constant selection, so
  // a batch whose gate lost writes not a single row
  const usersInsert = db
    .insert(users)
    .select(
      db
        .select({
          id: sql<string>`${userId}`.as("id"),
          email: sql<string | null>`${identity.verifiedEmail}`.as("email"),
          emailVerified: sql<number>`${identity.verifiedEmail === null ? 0 : 1}`.as(
            "email_verified",
          ),
          createdAt: sql<number>`${nowMs}`.as("created_at"),
          updatedAt: sql<number>`${nowMs}`.as("updated_at"),
        })
        .from(sql`(select 1)`)
        .where(gate.kind === "open" ? signupPolicyIs("open") : chained),
    )
    .returning({ id: users.id });
  const trailing = [
    db.insert(linkedIdentities).select(
      db
        .select({
          userId: sql<string>`${userId}`.as("user_id"),
          provider: sql<string>`${identity.provider}`.as("provider"),
          providerUserId: sql<string>`${identity.providerUserId}`.as("provider_user_id"),
          providerLogin: sql<string | null>`${identity.providerLogin}`.as("provider_login"),
          linkedAt: sql<number>`${nowMs}`.as("linked_at"),
        })
        .from(sql`(select 1)`)
        .where(chained),
    ),
    db.insert(organizations).select(
      db
        .select({
          id: sql<string>`${orgId}`.as("id"),
          slug: sql<string>`${`u-${userId.toLowerCase()}`}`.as("slug"),
          name: sql<string>`${identity.providerLogin ?? "personal"}`.as("name"),
          createdAt: sql<number>`${nowMs}`.as("created_at"),
        })
        .from(sql`(select 1)`)
        .where(chained),
    ),
    db.insert(memberships).select(
      db
        .select({
          orgId: sql<string>`${orgId}`.as("org_id"),
          userId: sql<string>`${userId}`.as("user_id"),
          role: sql<string>`'owner'`.as("role"),
        })
        .from(sql`(select 1)`)
        .where(chained),
    ),
    db.insert(userAuditEvents).select(
      db
        .select(
          guardedAuditSelectColumns({
            event: "auth.user_created",
            actor,
            nowMs,
            ...(gate.kind === "invite" ? { payload: { signupInviteId: gate.inviteId } } : {}),
          }),
        )
        .from(sql`(select 1)`)
        .where(chained),
    ),
    db.insert(userAuditEvents).select(
      db
        .select(
          guardedAuditSelectColumns({
            event: "auth.identity_linked",
            actor,
            nowMs,
            payload: { provider: identity.provider },
          }),
        )
        .from(sql`(select 1)`)
        .where(chained),
    ),
    db.insert(orgAuditEvents).select(
      db
        .select({
          ...guardedAuditSelectColumns({
            event: "org.created",
            actor,
            nowMs,
            payload: { personal: true },
          }),
          orgId: sql<string>`${orgId}`.as("org_id"),
        })
        .from(sql`(select 1)`)
        .where(chained),
    ),
    db.insert(orgAuditEvents).select(
      db
        .select({
          ...guardedAuditSelectColumns({
            event: "org.member_added",
            actor,
            nowMs,
            targetUserId: userId,
            payload: { role: "owner" },
          }),
          orgId: sql<string>`${orgId}`.as("org_id"),
        })
        .from(sql`(select 1)`)
        .where(chained),
    ),
  ] as const;
  return Effect.tryPromise({
    try: async () => {
      const createdRows =
        gate.kind === "invite"
          ? (
              await db.batch([
                // The consumption CAS (AUTH_SPEC §3): takes effect only
                // on pending + unexpired + acceptance-time policy
                // 'invite'. Same transaction as the creation — neither
                // the "a failed attempt burns a code only" shape nor
                // the "creation succeeded but the code is left
                // unconsumed" shape exists
                db
                  .update(signupInvites)
                  .set({ status: "used", usedByUserId: userId, usedAt: nowMs })
                  .where(
                    and(
                      eq(signupInvites.id, gate.inviteId),
                      eq(signupInvites.status, "pending"),
                      gt(signupInvites.expiresAt, nowMs),
                      signupPolicyIs("invite"),
                    ),
                  ),
                usersInsert,
                ...trailing,
              ])
            )[1]
          : (await db.batch([usersInsert, ...trailing]))[0];
      return createdRows.length === 1 ? userId : null;
    },
    catch: (error) => {
      if (isUniqueConflict(error)) {
        return new InsertConflictError();
      }
      // A D1 failure other than a conflict propagates as-is, as an
      // infrastructure defect
      throw error;
    },
  }).pipe(
    Effect.flatMap((created) =>
      created === null ? Effect.fail(new SignupGateLostError()) : Effect.succeed(created),
    ),
  );
}

/**
 * Refreshes the verified email at login (self-repair for the case where
 * a transient GitHub email-API outage missed it at signup). null never
 * wipes the existing value.
 */
function refreshVerifiedEmail(
  db: Db,
  userId: string,
  identity: VerifiedIdentity,
  nowMs: number,
): Effect.Effect<void> {
  if (identity.verifiedEmail === null) {
    return Effect.void;
  }
  const email = identity.verifiedEmail;
  return run(async () => {
    await db
      .update(users)
      .set({ email, emailVerified: 1, updatedAt: nowMs })
      .where(and(eq(users.id, userId), isNull(users.email)));
  });
}

/** Look up a signup invite code's pending row (does not consume — consumption is the creation batch's job). */
function findPendingSignupInvite(
  db: Db,
  tokenHashHex: string,
  nowMs: number,
): Effect.Effect<{ readonly id: string } | null> {
  return run(async () => {
    const row = await db
      .select({ id: signupInvites.id })
      .from(signupInvites)
      .where(
        and(
          eq(signupInvites.tokenHash, tokenHashHex),
          eq(signupInvites.status, "pending"),
          gt(signupInvites.expiresAt, nowMs),
        ),
      )
      .get();
    return row === undefined ? null : row;
  });
}

function makeIdentityRepo(db: Db): IdentityRepoShape {
  // The single idempotent entry point (§1-5) carrying the signupPolicy
  // gate (AUTH_SPEC §3). attempt is the re-judgment count of
  // SignupGateLost (the policy transitioned between the read and the
  // batch, or the invite code was concurrently consumed) — each
  // recursion re-reads the setting, so in a steady state it converges
  // in one pass. A setting that keeps oscillating without converging is
  // an operational anomaly (defect)
  const getOrCreateUser = (
    identity: VerifiedIdentity,
    nowMs: number,
    signupInviteTokenHash: string | null,
    attempt = 0,
  ): Effect.Effect<SignupGateResult> => {
    const attemptCreate = (gate: SignupGate): Effect.Effect<SignupGateResult> =>
      createUserBatch(db, identity, nowMs, gate).pipe(
        Effect.map((userId): SignupGateResult => ({ userId, created: true })),
        Effect.catchTag("InsertConflict", () => rerunLookup(db, identity)),
        Effect.catchTag("SignupGateLost", () =>
          attempt >= 2
            ? Effect.die(new Error("signup gate kept losing against concurrent policy changes"))
            : getOrCreateUser(identity, nowMs, signupInviteTokenHash, attempt + 1),
        ),
      );
    return Effect.flatMap(lookupLinkedUser(db, identity), (existing) => {
      if (existing !== null) {
        // An existing user bypasses the gate (AUTH_SPEC §3 — it only
        // blocks fresh creation). A presented code is not consumed
        return Effect.as(refreshVerifiedEmail(db, existing, identity, nowMs), {
          userId: existing,
          created: false,
        } satisfies ResolvedUser);
      }
      return Effect.flatMap(
        run(() => readSignupPolicy(db)),
        (policy) => {
          if (policy === "closed") {
            return Effect.succeed<SignupGateResult>({ denied: "policy-closed" });
          }
          if (policy === "open") {
            return attemptCreate({ kind: "open" });
          }
          if (signupInviteTokenHash === null) {
            return Effect.succeed<SignupGateResult>({ denied: "invite-required" });
          }
          return Effect.flatMap(
            findPendingSignupInvite(db, signupInviteTokenHash, nowMs),
            (invite) =>
              invite === null
                ? Effect.succeed<SignupGateResult>({ denied: "invite-invalid" })
                : attemptCreate({ kind: "invite", inviteId: invite.id }),
          );
        },
      );
    });
  };
  return {
    getOrCreateUser: (identity, nowMs, signupInviteTokenHash) =>
      getOrCreateUser(identity, nowMs, signupInviteTokenHash),
    lookupUser: (identity) => lookupLinkedUser(db, identity),
    listUserOrgs: (userId) => listUserOrgs(db, userId),
    providerLoginOf: (userId) => providerLoginOf(db, userId),
    signupPolicy: Effect.suspend(() => run(() => readSignupPolicy(db))),
    hasPendingSignupInvite: (tokenHashHex, nowMs) =>
      Effect.map(findPendingSignupInvite(db, tokenHashHex, nowMs), (row) => row !== null),
  };
}

/** The re-lookup after a batch conflict. Still not finding it here is a D1 failure (defect). */
function rerunLookup(db: Db, identity: VerifiedIdentity): Effect.Effect<ResolvedUser> {
  return Effect.flatMap(lookupLinkedUser(db, identity), (found) =>
    found === null
      ? Effect.die(new Error("linked identity insert failed without a conflicting row"))
      : Effect.succeed({ userId: found, created: false }),
  );
}

function providerLoginOf(db: Db, userId: string): Effect.Effect<string | null> {
  return run(async () => {
    const row = await db
      .select({ login: linkedIdentities.providerLogin })
      .from(linkedIdentities)
      .where(and(eq(linkedIdentities.userId, userId), eq(linkedIdentities.provider, "github")))
      .get();
    return row?.login ?? null;
  });
}

function listUserOrgs(db: Db, userId: string): Effect.Effect<readonly UserOrg[]> {
  return run(async () => {
    const rows = await db
      .select({
        orgId: organizations.id,
        slug: organizations.slug,
        name: organizations.name,
        role: memberships.role,
      })
      .from(memberships)
      .innerJoin(organizations, eq(memberships.orgId, organizations.id))
      .where(eq(memberships.userId, userId))
      .all();
    return rows.map((row) => ({ ...row, role: row.role as OrgRole }));
  });
}

// ---------------------------------------------------------------------------
// SessionRepo (§5. The id is a hash; the raw value never reaches this
// layer)
// ---------------------------------------------------------------------------

export interface SessionRepoShape {
  readonly insert: (
    idHash: string,
    userId: string,
    authMethod: string,
    nowMs: number,
    expiresAtMs: number,
  ) => Effect.Effect<void>;
  readonly findByHash: (idHash: string) => Effect.Effect<SessionRecord | null>;
  /** The sliding update (§5): advances last_used_at and expires_at. */
  readonly touch: (idHash: string, nowMs: number, expiresAtMs: number) => Effect.Effect<void>;
  /**
   * Explicit revocation (logout / server-side revocation). Records
   * auth.session_revoked in the same batch (AUDIT_SPEC §3.1). Expired-row
   * cleanup uses deleteByHash / deleteExpired (not a revocation event,
   * so nothing is recorded).
   */
  readonly revokeByHash: (idHash: string, nowMs: number) => Effect.Effect<void>;
  readonly deleteByHash: (idHash: string) => Effect.Effect<void>;
  /** The bulk cleanup of expired rows (called from cron; a row never presented disappears only here). */
  readonly deleteExpired: (nowMs: number) => Effect.Effect<void>;
}

export class SessionRepo extends Context.Service<SessionRepo, SessionRepoShape>()("SessionRepo") {}

function makeSessionRepo(db: Db): SessionRepoShape {
  return {
    // auth.login_succeeded is 1:1 with session creation (AUDIT_SPEC
    // §3.1 — auth.session_created is not an independent event), so it
    // is recorded in the same batch. The session id (= the same hash as
    // the stored id — not the raw value, AUTH_SPEC §10) is copied into
    // the payload for cross-checking against the revocation event
    insert: (idHash, userId, authMethod, nowMs, expiresAtMs) =>
      run(async () => {
        await db.batch([
          db.insert(sessions).values({
            id: idHash,
            userId,
            authMethod,
            createdAt: nowMs,
            expiresAt: expiresAtMs,
            lastUsedAt: nowMs,
          }),
          userAuditInsert(db, nowMs, {
            event: "auth.login_succeeded",
            actor: { userId, authMethod },
            payload: { sessionId: idHash },
          }),
        ]);
      }),
    findByHash: (idHash) =>
      run(async () => {
        const row = await db
          .select({
            userId: sessions.userId,
            authMethod: sessions.authMethod,
            expiresAt: sessions.expiresAt,
          })
          .from(sessions)
          .where(eq(sessions.id, idHash))
          .get();
        return row === undefined
          ? null
          : { userId: row.userId, authMethod: row.authMethod, expiresAtMs: row.expiresAt };
      }),
    touch: (idHash, nowMs, expiresAtMs) =>
      run(async () => {
        await db
          .update(sessions)
          .set({ lastUsedAt: nowMs, expiresAt: expiresAtMs })
          .where(eq(sessions.id, idHash));
      }),
    revokeByHash: (idHash, nowMs) =>
      run(async () => {
        // The event is written after observing the deletion's success
        // via returning (the actor is also copied from it). A read →
        // delete two-step would let two concurrent logouts both succeed
        // on the SELECT and record 2 rows for 1 revocation. Splitting
        // the delete and the append into 2 statements leaves a
        // theoretical window where "only the delete succeeded and the
        // event is missing", but we fall toward the missing side over
        // the duplicate side. No row = no-op (a nonexistent revocation
        // is not evented)
        const deleted = await db
          .delete(sessions)
          .where(eq(sessions.id, idHash))
          .returning({ userId: sessions.userId, authMethod: sessions.authMethod });
        const row = deleted[0];
        if (row === undefined) {
          return;
        }
        await userAuditInsert(db, nowMs, {
          event: "auth.session_revoked",
          actor: { userId: row.userId, authMethod: row.authMethod },
          payload: { sessionId: idHash },
        });
      }),
    deleteByHash: (idHash) =>
      run(async () => {
        await db.delete(sessions).where(eq(sessions.id, idHash));
      }),
    deleteExpired: (nowMs) =>
      run(async () => {
        await db.delete(sessions).where(lte(sessions.expiresAt, nowMs));
      }),
  };
}

// ---------------------------------------------------------------------------
// TokenRepo (§6. The token_hash comparison additionally uses a
// timing-safe comparison at the service layer)
// ---------------------------------------------------------------------------

export interface NewApiToken {
  readonly id: string;
  readonly userId: string;
  readonly name: string;
  readonly tokenHash: string;
  readonly tokenPrefix: string;
  readonly scopes: readonly TokenScope[];
  /** The validity period fixed at issuance (AUTH_SPEC §6's default TTL — W3a). */
  readonly expiresAtMs: number;
  readonly createdAtMs: number;
}

export interface TokenRepoShape {
  /**
   * The same (user, name) rotates while revoking the existing token; a
   * different name is conditionally issued only under `limit`. Each
   * path runs as a D1 atomic batch, so even concurrent issuance never
   * allows a duplicate name or an over-limit distinct name. false =
   * quota rejection.
   *
   * The replaced old token id rides on `auth.token_created`'s payload
   * as `replacedTokenId` (absent on a fresh issuance — AUDIT_SPEC §3.1).
   */
  readonly issueForUserWithinLimit: (token: NewApiToken, limit: number) => Effect.Effect<boolean>;
  readonly findByHash: (tokenHash: string) => Effect.Effect<ApiTokenRecord | null>;
  readonly touchLastUsed: (id: string, nowMs: number) => Effect.Effect<void>;
  /**
   * The user's own token list (AUTH_SPEC §6 — W3a). token_hash is not
   * among the selected columns (a distribution surface — it does not
   * even exist in ApiTokenSummary's structure). Expired rows are
   * returned too (inventory targets — only verification drops them to
   * 401). Ascending created_at; ties by id.
   */
  readonly listForUser: (userId: string) => Effect.Effect<readonly ApiTokenSummary[]>;
  /**
   * Explicit revocation. Enforces id × user ownership and records
   * auth.token_revoked (§3.1 / S8). actor is the principal that executed
   * the revocation (on a targeted revocation it may be a session /
   * another token — AUDIT_SPEC §2). The return value = whether a row
   * was actually deleted (false is how the caller derives the uniform
   * 404 — §6's existence concealment).
   */
  readonly revokeById: (
    id: string,
    userId: string,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<boolean>;
}

export class TokenRepo extends Context.Service<TokenRepo, TokenRepoShape>()("TokenRepo") {}

function tokenInsertSelect(db: Db, token: NewApiToken, condition: SQL) {
  return db
    .insert(apiTokens)
    .select(
      db
        .select({
          id: sql<string>`${token.id}`.as("id"),
          userId: sql<string>`${token.userId}`.as("user_id"),
          name: sql<string>`${token.name}`.as("name"),
          tokenHash: sql<string>`${token.tokenHash}`.as("token_hash"),
          tokenPrefix: sql<string>`${token.tokenPrefix}`.as("token_prefix"),
          scopes: sql<string>`${JSON.stringify(token.scopes)}`.as("scopes"),
          expiresAt: sql<number>`${token.expiresAtMs}`.as("expires_at"),
          createdAt: sql<number>`${token.createdAtMs}`.as("created_at"),
          lastUsedAt: sql<number | null>`${null}`.as("last_used_at"),
        })
        .from(sql`(select 1)`)
        .where(condition),
    )
    .returning({ id: apiTokens.id });
}

function tokenCreatedAuditAfterInsert(db: Db, token: NewApiToken) {
  return db.insert(userAuditEvents).select(
    db
      .select(
        guardedAuditSelectColumns({
          event: "auth.token_created",
          actor: { userId: token.userId },
          nowMs: token.createdAtMs,
          payload: { tokenId: token.id, name: token.name, scopes: token.scopes },
        }),
      )
      .from(apiTokens)
      .where(and(eq(apiTokens.id, token.id), sql`changes() = 1`)),
  );
}

/**
 * The rotation of an existing same-name token. Because the first audit
 * INSERT reads the old id, replacedTokenId matches the row that is
 * actually deleted in the same batch.
 */
async function rotateExistingToken(db: Db, token: NewApiToken): Promise<boolean> {
  const basePayload = JSON.stringify({
    tokenId: token.id,
    name: token.name,
    scopes: token.scopes,
  });
  const sameTokenName = and(eq(apiTokens.userId, token.userId), eq(apiTokens.name, token.name));
  const results = await db.batch([
    db.insert(userAuditEvents).select(
      db
        .select(
          guardedAuditSelectColumns({
            event: "auth.token_created",
            actor: { userId: token.userId },
            nowMs: token.createdAtMs,
            payloadSql: sql<string>`json_patch(${basePayload}, json_object('replacedTokenId', ${apiTokens.id}))`,
          }),
        )
        .from(apiTokens)
        .where(sameTokenName),
    ),
    db
      .delete(apiTokens)
      .where(and(sameTokenName, sql`changes() = 1`))
      .returning({ id: apiTokens.id }),
    tokenInsertSelect(db, token, sql`changes() = 1`),
  ]);
  return results[2].length === 1;
}

/** Folds the limit check + INSERT of a new-name token into one statement. */
async function createNewTokenWithinLimit(
  db: Db,
  token: NewApiToken,
  limit: number,
): Promise<boolean> {
  const underLimit = sql<boolean>`(
    select count(*) from ${apiTokens}
    where ${apiTokens.userId} = ${token.userId}
  ) < ${limit}`;
  const nameAvailable = sql<boolean>`not exists (
    select 1 from ${apiTokens}
    where ${apiTokens.userId} = ${token.userId}
      and ${apiTokens.name} = ${token.name}
  )`;
  const results = await db.batch([
    tokenInsertSelect(db, token, sql`${underLimit} and ${nameAvailable}`),
    tokenCreatedAuditAfterInsert(db, token),
  ]);
  return results[0].length === 1;
}

function makeTokenRepo(db: Db): TokenRepoShape {
  return {
    // The admission on the issuance limit is the job of the repo's
    // conditional INSERT. A service-layer count → insert would be a
    // separate D1 round-trip, and concurrent issuances under different
    // names could observe the same under-limit and exceed it. A
    // same-name rotation is allowed even at the limit and also keeps
    // the old id's audit in the same batch.
    issueForUserWithinLimit: (token, limit) =>
      run(async () => {
        if (await rotateExistingToken(db, token)) {
          return true;
        }
        if (await createNewTokenWithinLimit(db, token, limit)) {
          return true;
        }
        // A race where a same-name token appeared between the first
        // existence check and the new INSERT. To distinguish it from a
        // quota rejection of a new name, the rotation is retried last
        return rotateExistingToken(db, token);
      }),
    findByHash: (tokenHash) => run(() => findTokenByHash(db, tokenHash)),
    touchLastUsed: (id, nowMs) =>
      run(async () => {
        await db.update(apiTokens).set({ lastUsedAt: nowMs }).where(eq(apiTokens.id, id));
      }),
    listForUser: (userId) =>
      run(async () => {
        // token_hash is not among the selected columns (a distribution
        // surface — the note in auth-domain.ts). Expired rows are
        // returned too: the list is an inventory surface, and unlike
        // revocation (row deletion) an expired row stays visible as
        // stock (the user can clean it up with a targeted revocation)
        const rows = await db
          .select({
            id: apiTokens.id,
            name: apiTokens.name,
            tokenPrefix: apiTokens.tokenPrefix,
            scopes: apiTokens.scopes,
            createdAt: apiTokens.createdAt,
            lastUsedAt: apiTokens.lastUsedAt,
            expiresAt: apiTokens.expiresAt,
          })
          .from(apiTokens)
          .where(eq(apiTokens.userId, userId))
          .orderBy(apiTokens.createdAt, apiTokens.id)
          .all();
        return rows.map((row): ApiTokenSummary => {
          const scopes = parseTokenScopes(row.scopes);
          if (scopes === null) {
            // The same discipline as findTokenByHash: a column only our
            // own write path can produce being broken = an
            // implementation bug / DB corruption (the row is never
            // silently dropped)
            throw new Error("stored token scopes are not a valid scope array");
          }
          return {
            id: row.id,
            name: row.name,
            tokenPrefix: row.tokenPrefix,
            scopes,
            createdAtMs: row.createdAt,
            lastUsedAtMs: row.lastUsedAt,
            expiresAtMs: row.expiresAt,
          };
        });
      }),
    revokeById: (id, userId, nowMs, actor) =>
      run(async () => {
        // The event is written after observing the deletion's success
        // via returning (same shape as revokeByHash). A concurrent
        // revoke can pass the caller's findByHash on both sides, so an
        // unconditional batch could record multiple token_revoked for 1
        // revocation (overcounting). We fall toward the missing side
        // over the duplicate side
        const deleted = await db
          .delete(apiTokens)
          // Deleting by id alone would let the token-id-addressed admin
          // API (W3a's targeted revocation) revoke another user's
          // token while mis-recording the audit actor as the calling
          // user. The ownership condition is enforced at the repo
          // boundary; 0 rows = the caller's uniform 404 (§6)
          .where(and(eq(apiTokens.id, id), eq(apiTokens.userId, userId)))
          .returning({ id: apiTokens.id });
        if (deleted.length === 0) {
          return false;
        }
        await userAuditInsert(db, nowMs, {
          event: "auth.token_revoked",
          actor,
          payload: { tokenId: id },
        });
        return true;
      }),
  };
}

async function findTokenByHash(db: Db, tokenHash: string): Promise<ApiTokenRecord | null> {
  const row = await db
    .select({
      id: apiTokens.id,
      userId: apiTokens.userId,
      tokenHash: apiTokens.tokenHash,
      scopes: apiTokens.scopes,
      expiresAt: apiTokens.expiresAt,
      lastUsedAt: apiTokens.lastUsedAt,
    })
    .from(apiTokens)
    .where(eq(apiTokens.tokenHash, tokenHash))
    .get();
  if (row === undefined) {
    return null;
  }
  const scopes = parseTokenScopes(row.scopes);
  if (scopes === null) {
    // A column only our own write path can produce being broken = an
    // implementation bug / DB corruption
    throw new Error("stored token scopes are not a valid scope array");
  }
  return {
    id: row.id,
    userId: row.userId,
    tokenHash: row.tokenHash,
    scopes,
    expiresAtMs: row.expiresAt,
    lastUsedAtMs: row.lastUsedAt,
  };
}

// ---------------------------------------------------------------------------
// RecoveryRepo (AUTH_SPEC §13. At most one blob per user)
// ---------------------------------------------------------------------------

/**
 * The blob-fetch rate limit (AUTH_SPEC §13-3: 5 per hour per user).
 * Since KL3 (§13-8) it is counted in one window **summed by kind** with
 * passkey / guardian-group wrap fetches (`key_wrap_windows` kind =
 * blob-fetch — KeyWrapRepo.consumeWindow). The limit value is
 * unchanged.
 */
export const RECOVERY_FETCH_LIMIT = KEY_BLOB_FETCH_LIMIT;

interface RecoveryRepoShape {
  /**
   * Registration / re-issuance = a replacing upsert (§13-1; the old
   * wrap disappears the moment the new one is accepted). Records
   * auth.recovery_code_reissued in the same batch (AUDIT_SPEC §3.1 /
   * AUTH_SPEC §13-5; the first registration is the same replacing
   * acceptance, hence the same event).
   */
  readonly upsert: (
    userId: string,
    wrap: { readonly suite: string; readonly nonceHex: string; readonly ciphertextHex: string },
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<void>;
  readonly find: (userId: string) => Effect.Effect<RecoveryWrapRecord | null>;
  /**
   * Advances the fixed-window count and returns whether the fetch is
   * allowed (§13-3). When no row exists it is allowed (a 404 is not
   * counted — the caller judges via find). A read → conditional-update
   * pair of statements, best-effort in that concurrent requests may
   * slightly exceed the count. When allowed, records
   * auth.recovery_blob_fetched (a watch-listed event — AUDIT_SPEC §3.1)
   * in the same batch as the count update (a denial = no distribution
   * is not recorded).
   */
  readonly recordFetch: (
    userId: string,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<RecoveryFetchDecision>;
}

export class RecoveryRepo extends Context.Service<RecoveryRepo, RecoveryRepoShape>()(
  "RecoveryRepo",
) {}

function makeRecoveryRepo(db: Db, keyWraps: KeyWrapRepoShape): RecoveryRepoShape {
  return {
    upsert: (userId, wrap, nowMs, actor) =>
      run(async () => {
        await db.batch([
          // A re-issuance is a new blob, so the fetch window (the
          // summed window — §13-8) is reset too (the trial history
          // against the old blob is not carried over to the new one)
          db
            .delete(keyWrapWindows)
            .where(and(eq(keyWrapWindows.userId, userId), eq(keyWrapWindows.kind, "blob-fetch"))),
          db
            .insert(recoveryWraps)
            .values({
              userId,
              suite: wrap.suite,
              nonceHex: wrap.nonceHex,
              ciphertextHex: wrap.ciphertextHex,
              createdAt: nowMs,
              updatedAt: nowMs,
            })
            .onConflictDoUpdate({
              target: recoveryWraps.userId,
              set: {
                suite: wrap.suite,
                nonceHex: wrap.nonceHex,
                ciphertextHex: wrap.ciphertextHex,
                updatedAt: nowMs,
              },
            }),
          userAuditInsert(db, nowMs, { event: "auth.recovery_code_reissued", actor }),
        ]);
      }),
    find: (userId) =>
      run(async () => {
        const row = await db
          .select({
            suite: recoveryWraps.suite,
            nonceHex: recoveryWraps.nonceHex,
            ciphertextHex: recoveryWraps.ciphertextHex,
            updatedAt: recoveryWraps.updatedAt,
          })
          .from(recoveryWraps)
          .where(eq(recoveryWraps.userId, userId))
          .get();
        return row === undefined
          ? null
          : {
              suite: row.suite,
              nonceHex: row.nonceHex,
              ciphertextHex: row.ciphertextHex,
              updatedAtMs: row.updatedAt,
            };
      }),
    // Since KL3 (§13-8) the fetch count is kept in the fixed window
    // summed with passkey / guardian-group wrap fetches
    // (KeyWrapRepo.consumeWindow — a single conditional UPSERT + a
    // changes() = 1 guarded audit bundled in). The caller judges the
    // 404 via find first, so an unregistered user does not consume the
    // window (the §13-3 line is unchanged)
    recordFetch: (userId, nowMs, actor) =>
      keyWraps.consumeWindow({
        userId,
        kind: "blob-fetch",
        limit: RECOVERY_FETCH_LIMIT,
        nowMs,
        audit: { event: "auth.recovery_blob_fetched", actor },
      }),
  };
}

// ---------------------------------------------------------------------------
// OrgRepo (§9-1 org roles. Not involved in project access)
// ---------------------------------------------------------------------------

interface OrgRepoShape {
  readonly roleOf: (orgId: string, userId: string) => Effect.Effect<OrgRole | null>;
}

export class OrgRepo extends Context.Service<OrgRepo, OrgRepoShape>()("OrgRepo") {}

function makeOrgRepo(db: Db): OrgRepoShape {
  return {
    roleOf: (orgId, userId) =>
      run(async () => {
        const row = await db
          .select({ role: memberships.role })
          .from(memberships)
          .where(and(eq(memberships.orgId, orgId), eq(memberships.userId, userId)))
          .get();
        return row === undefined ? null : (row.role as OrgRole);
      }),
  };
}

// ---------------------------------------------------------------------------
// ProjectRepo (§11-3. The org-attribution metadata + the §11-5
// membership projection. Neither is an authorization table — the
// projection is a discovery-only candidate index and is never used in
// an authorization decision. The source of truth is the membership
// chain — CRYPTO_SPEC §6.4)
// ---------------------------------------------------------------------------

interface ProjectRepoShape {
  /**
   * An idempotent insert (§11-3 including the repair path). An existing
   * row is left as-is. Records org.project_created (AUDIT_SPEC §3.2) and
   * the genesis actor's (owner's) membership projection row (§11-5) in
   * the same batch. By the batch's atomicity, when the insert does not
   * go through because of a conflict with an existing row, the audit
   * row is rolled back too (a whiffed insert never duplicates just the
   * event). The projection row's insert is onConflictDoNothing: on the
   * repair path (§11-3) a lazy upsert (§11-5's (4)) may have already
   * placed the row, and that conflict must not roll back even the
   * projects row's insert.
   */
  readonly insertIfAbsent: (
    projectId: string,
    orgId: string,
    ownerUserId: string,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<void>;
  readonly exists: (projectId: string) => Effect.Effect<boolean>;
  /**
   * The org's active project count (the decision input of AUTH_SPEC
   * §11-3's acceptance limit). In v1 it counts every `projects` row of
   * the org (there is no delete API and no tombstone — when deletion is
   * introduced an exclusion condition is added). A count on the
   * `proj_org` index. It is a best-effort judgment input with no
   * atomicity against DO acceptance (§11-3 — a slight excess from
   * concurrent inits is accepted).
   */
  readonly countInOrg: (orgId: string) => Effect.Effect<number>;
  /**
   * Maintaining the projection (§11-5): the row insert after an
   * add_member acceptance and the lazy insert on a successful chain
   * fetch (self-repair of a missing row + the unmanned backfill of
   * pre-projection projects). Idempotent (equivalent to INSERT OR
   * IGNORE).
   */
  readonly upsertMember: (projectId: string, userId: string, nowMs: number) => Effect.Effect<void>;
  /**
   * Maintaining the projection (§11-5): deletion of a stale row the DO
   * answered non-member on at list read-time verification, after a
   * remove_member acceptance (convergence toward the chain truth).
   * Idempotent.
   */
  readonly deleteMember: (projectId: string, userId: string) => Effect.Effect<void>;
  /**
   * The candidate enumeration of the list (§11-5): the project_ids of
   * the user's own projection rows, ascending, up to `limit` rows from
   * the exclusive cursor `afterProjectId` (null = from the head).
   * Candidates only — the caller's DO check decides whether they may go
   * on the response.
   *
   * `withinProjectIds` is the filter performing the intersection with
   * the token scope **at the candidate-index stage** (null = no
   * restriction). `nextAfter` comes off the tail of the candidate page,
   * so leaving the intersection to a later stage (narrowing the
   * response rows) would let an out-of-scope project_id ride the cursor
   * and leak — the candidate space itself is closed inside the scope.
   */
  readonly listMemberProjectIds: (
    userId: string,
    afterProjectId: string | null,
    limit: number,
    withinProjectIds: readonly string[] | null,
  ) => Effect.Effect<readonly string[]>;
}

export class ProjectRepo extends Context.Service<ProjectRepo, ProjectRepoShape>()("ProjectRepo") {}

/**
 * The chunk width of the scope-intersection IN (the §11-5 candidate
 * enumeration). Sized with headroom inside the budget left after
 * subtracting the 3 parameters userId / after / limit from D1's
 * per-query bound-parameter cap (100 — Cloudflare D1 limits). Pushing
 * the token scope's issuance-time cap (100 entries — AUTH_SPEC §6 /
 * api-schema) into a single IN would exceed the cap, so when changing
 * any of these limits, re-verify the consistency with this value.
 */
const SCOPE_FILTER_CHUNK_SIZE = 50;

function makeProjectRepo(db: Db): ProjectRepoShape {
  return {
    insertIfAbsent: (projectId, orgId, ownerUserId, nowMs, actor) =>
      run(async () => {
        try {
          await db.batch([
            db.insert(projects).values({ id: projectId, orgId, createdAt: nowMs }),
            db
              .insert(projectMembers)
              .values({ projectId, userId: ownerUserId, createdAt: nowMs })
              .onConflictDoNothing(),
            orgAuditInsert(db, nowMs, {
              event: "org.project_created",
              actor,
              orgId,
              projectId,
            }),
          ]);
        } catch (error) {
          // A PK conflict = already created. The whole batch rolls back,
          // so both insert and audit are a no-op (idempotent). No
          // execution order exists where only the audit row survives.
          // A non-conflict is a defect
          if (!isUniqueConflict(error)) {
            throw error;
          }
        }
      }),
    exists: (projectId) =>
      run(async () => {
        const row = await db
          .select({ id: projects.id })
          .from(projects)
          .where(eq(projects.id, projectId))
          .get();
        return row !== undefined;
      }),
    countInOrg: (orgId) =>
      run(async () => {
        const row = await db
          .select({ n: count() })
          .from(projects)
          .where(eq(projects.orgId, orgId))
          .get();
        return row?.n ?? 0;
      }),
    upsertMember: (projectId, userId, nowMs) =>
      run(async () => {
        await db
          .insert(projectMembers)
          .values({ projectId, userId, createdAt: nowMs })
          .onConflictDoNothing();
      }),
    deleteMember: (projectId, userId) =>
      run(async () => {
        await db
          .delete(projectMembers)
          .where(and(eq(projectMembers.projectId, projectId), eq(projectMembers.userId, userId)));
      }),
    listMemberProjectIds: (userId, afterProjectId, limit, withinProjectIds) =>
      run(async () => {
        const pageQuery = (
          scopeChunk: readonly string[] | null,
        ): Promise<{ projectId: string }[]> => {
          const conditions = [eq(projectMembers.userId, userId)];
          if (afterProjectId !== null) {
            conditions.push(gt(projectMembers.projectId, afterProjectId));
          }
          if (scopeChunk !== null) {
            conditions.push(inArray(projectMembers.projectId, [...scopeChunk]));
          }
          return db
            .select({ projectId: projectMembers.projectId })
            .from(projectMembers)
            .where(and(...conditions))
            .orderBy(projectMembers.projectId)
            .limit(limit)
            .all();
        };
        if (withinProjectIds === null) {
          return (await pageQuery(null)).map((row) => row.projectId);
        }
        // The scope-intersection IN is issued chunked: D1's per-query
        // bound-parameter cap is 100 and the token scope's schema cap is
        // also 100 entries (api-schema auth-api.ts) — a single IN would
        // exceed the cap together with the 3 parameters userId / after
        // / limit, and a legitimately issued wide-scope token's list
        // would hard-fail. Each chunk returns an ascending run of up to
        // `limit` rows, so concatenate + sort-all + cut-at-limit gives
        // the same page as a single query (the chunks are disjoint ID
        // sets). The loop shape is also safe against old rows whose
        // stored scope exceeds the issuance-time cap
        const merged: string[] = [];
        for (let offset = 0; offset < withinProjectIds.length; offset += SCOPE_FILTER_CHUNK_SIZE) {
          const chunk = withinProjectIds.slice(offset, offset + SCOPE_FILTER_CHUNK_SIZE);
          merged.push(...(await pageQuery(chunk)).map((row) => row.projectId));
        }
        return merged.toSorted().slice(0, limit);
      }),
  };
}

// ---------------------------------------------------------------------------
// InviteRepo (AUTH_SPEC §15. Invite records and invite.* audit appended
// in the same batch)
// ---------------------------------------------------------------------------

/** The §15-1 drafted value: an invitation's validity (issuance + 7 days). */
export const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * The §15-2 drafted value: the issuance rate window (30 per hour per
 * project). The implementation shape is a lookback count of "the
 * invitations row count in the last hour" (the same shape as
 * auth.login_failed — audit.ts — with no additional window state).
 * Never exceeding 30 in any one-hour interval = it can never be looser
 * than the spec's fixed window (it lands on the stricter side by the
 * absence of a bucket-boundary reset). retryAfterSeconds is derived
 * from when the oldest in-window issuance leaves the window.
 */
const INVITE_ISSUE_WINDOW_MS = 60 * 60 * 1000;
export const INVITE_ISSUE_WINDOW_LIMIT = 30;

/** The §15-2 drafted value: the pending-invite cap (100 per project; expired ones are not counted). */
export const MAX_PENDING_INVITES_PER_PROJECT = 100;

interface InviteCreateInput {
  readonly id: string;
  readonly projectId: string;
  readonly role: InviteRole;
  /** The scope to be granted (part of the issuance text — §15-2, 2026-09-14 ES). */
  readonly scope: InviteScope;
  readonly inviterUserId: string;
  /** The issuance text (CRYPTO_SPEC §6.5 — the server stores it without verifying). */
  readonly issuance: InviteIssuance;
}

interface InviteRepoShape {
  /**
   * Issuance (§15-2). The acceptance policy's judgment order is pinned
   * to the spec's written order: the pending cap → the rate window
   * (lookback counting — see the note on INVITE_ISSUE_WINDOW_MS). Both
   * counts are re-evaluated inside the same `INSERT … SELECT … WHERE`
   * statement, so even concurrent issuance never exceeds the limits. On
   * acceptance, invite.created (AUDIT_SPEC §3.2) is placed in the same
   * batch as the changes()-guarded INSERT…SELECT and recorded 1:1 with
   * the creation.
   */
  readonly create: (
    input: InviteCreateInput,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<InviteIssueDecision>;
  /** Resolution by link public key (the acceptance path — holding the link key is the capability). */
  readonly findByLinkPub: (linkPubHex: string) => Effect.Effect<InvitationRecord | null>;
  /** The id resolution under a project (the revocation path). */
  readonly findById: (projectId: string, id: string) => Effect.Effect<InvitationRecord | null>;
  /** The list (§15-2). The acceptance block included — the input of the inviter client's §6.5 independent verification. */
  readonly listForProject: (projectId: string) => Effect.Effect<readonly InvitationRecord[]>;
  /**
   * The single-use CAS of acceptance (pending → accepted — §15-1). The
   * conditional UPDATE and the invite.accepted INSERT…SELECT guarded by
   * `changes() = 1` are issued in the same batch (AUDIT_SPEC §5.2's
   * same-transaction principle). D1 documents a batch as sequential,
   * non-parallel, and a single transaction, and by that sequentiality
   * changes() refers to the result of the immediately preceding UPDATE
   * (the digestion order of RETURNING statements is not documented, so
   * this property is also pinned as actual behavior by the CAS-defeat
   * test in invites.test.ts) — on a CAS defeat the audit row stays at
   * 0 rows too. The return value is win/loss only (the caller derives
   * the defeat reason by re-reading).
   */
  readonly acceptCas: (
    input: InviteAcceptInput,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<boolean>;
  /**
   * The revocation CAS (pending | accepted → revoked). Revoking an
   * expired pending is allowed too (an admin-operation cleanup). On
   * acceptance invite.revoked is recorded in the same batch (the same
   * changes() guard as acceptCas). Has no effect on completed / revoked
   * (the caller derives the 410 by re-reading).
   */
  readonly revokeCas: (
    projectId: string,
    id: string,
    payload: { readonly role: InviteRole },
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<boolean>;
  /**
   * The accepted → completed reconciliation at add_member acceptance
   * (§15-2. It updates a derived state; the source of truth is the
   * chain. §15-4: the evidence is chain.member_added — no independent
   * event is written). The key-match conditions (both enc / sig)
   * refine "this acceptance was fulfilled by this add_member" — an
   * accepted invite under a different key is kept as-is and stays
   * visible in the list.
   */
  readonly completeAccepted: (target: InviteCompletionTarget) => Effect.Effect<void>;
}

export class InviteRepo extends Context.Service<InviteRepo, InviteRepoShape>()("InviteRepo") {}

/** An invitation row (the shape of the select result — the Drizzle type never leaves this boundary). */
interface InvitationRow {
  readonly id: string;
  readonly projectId: string;
  readonly role: string;
  readonly scopeKind: string;
  readonly scopeEnvironments: string;
  readonly inviterUserId: string;
  readonly status: string;
  readonly expiresAt: number;
  readonly inviteeUserId: string | null;
  readonly inviteeEncPub: string | null;
  readonly inviteeSigPub: string | null;
  readonly acceptSignature: string | null;
  readonly linkSignature: string | null;
  readonly acceptedAt: number | null;
  readonly createdAt: number;
  readonly linkPub: string;
  readonly headHash: string;
  readonly headSeq: number;
  readonly issueSignature: string;
}

/** The acceptance block (only when all 6 columns are populated — status at accepted or later). */
function acceptanceOf(row: InvitationRow): InvitationRecord["acceptance"] {
  return row.inviteeUserId !== null &&
    row.inviteeEncPub !== null &&
    row.inviteeSigPub !== null &&
    row.acceptSignature !== null &&
    row.linkSignature !== null &&
    row.acceptedAt !== null
    ? {
        inviteeUserId: row.inviteeUserId,
        inviteeEncPubHex: row.inviteeEncPub,
        inviteeSigPubHex: row.inviteeSigPub,
        acceptSignatureHex: row.acceptSignature,
        linkSignatureHex: row.linkSignature,
        acceptedAtMs: row.acceptedAt,
      }
    : null;
}

/** The issuance text (CRYPTO_SPEC §6.5 — all 4 columns NOT NULL). */
function issuanceOf(row: InvitationRow): InvitationRecord["issuance"] {
  return {
    linkPubHex: row.linkPub,
    headHashHex: row.headHash,
    headSeq: row.headSeq,
    issueSignatureHex: row.issueSignature,
  };
}

/**
 * The scope column (a JSON-array string) → the domain representation.
 * The column holds a JSON.stringify of a value Schema-checked at
 * issuance, but rather than making a broken row unacceptable via a
 * throw, it falls fail-closed to an empty `listed` (= grants no
 * environment)
 */
function scopeOf(row: InvitationRow): InviteScope {
  let ids: readonly string[] = [];
  try {
    const parsed: unknown = JSON.parse(row.scopeEnvironments);
    if (Array.isArray(parsed) && parsed.every((id) => typeof id === "string")) {
      ids = parsed;
    }
  } catch {
    ids = [];
  }
  return row.scopeKind === "all" && ids.length === 0
    ? { scopeKind: "all", scopeEnvironmentIds: [] }
    : { scopeKind: "listed", scopeEnvironmentIds: ids };
}

/** Row → the domain representation. */
function toInvitationRecord(row: InvitationRow): InvitationRecord {
  return {
    id: row.id,
    projectId: row.projectId,
    issuance: issuanceOf(row),
    role: row.role as InviteRole,
    scope: scopeOf(row),
    inviterUserId: row.inviterUserId,
    status: row.status as InviteStatus,
    expiresAtMs: row.expiresAt,
    createdAtMs: row.createdAt,
    acceptance: acceptanceOf(row),
  };
}

/**
 * Maps a D1 UNIQUE constraint violation to the issuance 409
 * (`invitations.id` / `inv_link_pub`). Any other error is null (the
 * caller re-throws — never swallowed).
 */
function inviteUniqueConflictOf(error: unknown): "id" | "linkPub" | null {
  // D1 carries a constraint error on either message or cause (varies by runtime)
  const cause = error instanceof Error ? error.cause : undefined;
  const message = `${error instanceof Error ? error.message : String(error)} ${
    cause instanceof Error ? cause.message : ""
  }`;
  if (!/UNIQUE constraint failed/.test(message)) {
    return null;
  }
  if (message.includes("invitations.link_pub")) {
    return "linkPub";
  }
  return message.includes("invitations.id") ? "id" : null;
}

/** Re-evaluates both the pending and the lookback caps inside the same INSERT statement. */
function conditionalInviteInsert(db: Db, input: InviteCreateInput, nowMs: number) {
  const pendingAvailable = sql<boolean>`(
    select count(*) from ${invitations}
    where ${invitations.projectId} = ${input.projectId}
      and ${invitations.status} = 'pending'
      and ${invitations.expiresAt} > ${nowMs}
  ) < ${MAX_PENDING_INVITES_PER_PROJECT}`;
  const windowAvailable = sql<boolean>`(
    select count(*) from ${invitations}
    where ${invitations.projectId} = ${input.projectId}
      and ${invitations.createdAt} >= ${nowMs - INVITE_ISSUE_WINDOW_MS}
  ) < ${INVITE_ISSUE_WINDOW_LIMIT}`;
  return db
    .insert(invitations)
    .select(
      db
        .select({
          id: sql<string>`${input.id}`.as("id"),
          projectId: sql<string>`${input.projectId}`.as("project_id"),
          linkPub: sql<string>`${input.issuance.linkPubHex}`.as("link_pub"),
          headHash: sql<string>`${input.issuance.headHashHex}`.as("head_hash"),
          headSeq: sql<number>`${input.issuance.headSeq}`.as("head_seq"),
          issueSignature: sql<string>`${input.issuance.issueSignatureHex}`.as("issue_signature"),
          role: sql<string>`${input.role}`.as("role"),
          scopeKind: sql<string>`${input.scope.scopeKind}`.as("scope_kind"),
          scopeEnvironments: sql<string>`${JSON.stringify(input.scope.scopeEnvironmentIds)}`.as(
            "scope_environments",
          ),
          inviterUserId: sql<string>`${input.inviterUserId}`.as("inviter_user_id"),
          status: sql<string>`'pending'`.as("status"),
          expiresAt: sql<number>`${nowMs + INVITE_TTL_MS}`.as("expires_at"),
          createdAt: sql<number>`${nowMs}`.as("created_at"),
        })
        .from(sql`(select 1)`)
        .where(and(pendingAvailable, windowAvailable)),
    )
    .returning({ id: invitations.id });
}

/**
 * Derives in spec order why the conditional INSERT produced 0 rows.
 * For explaining the rejection only; the admission itself is the job of
 * conditionalInviteInsert's single statement.
 */
async function inviteIssueRejection(
  db: Db,
  projectId: string,
  nowMs: number,
): Promise<Exclude<InviteIssueDecision, { readonly kind: "created" }> | null> {
  const pendingRow = await db
    .select({ n: count() })
    .from(invitations)
    .where(
      and(
        eq(invitations.projectId, projectId),
        eq(invitations.status, "pending"),
        gt(invitations.expiresAt, nowMs),
      ),
    )
    .get();
  if ((pendingRow?.n ?? 0) >= MAX_PENDING_INVITES_PER_PROJECT) {
    return { kind: "pending-limit", limit: MAX_PENDING_INVITES_PER_PROJECT };
  }
  const windowRow = await db
    .select({ n: count(), oldest: min(invitations.createdAt) })
    .from(invitations)
    .where(
      and(
        eq(invitations.projectId, projectId),
        gte(invitations.createdAt, nowMs - INVITE_ISSUE_WINDOW_MS),
      ),
    )
    .get();
  if ((windowRow?.n ?? 0) < INVITE_ISSUE_WINDOW_LIMIT) {
    return null;
  }
  const oldest = windowRow?.oldest ?? nowMs;
  const remainingMs = oldest + INVITE_ISSUE_WINDOW_MS - nowMs;
  return {
    kind: "rate-limited",
    retryAfterSeconds: Math.max(1, Math.ceil(remainingMs / 1000)),
  };
}

function makeInviteRepo(db: Db): InviteRepoShape {
  const findWhere = async (condition: ReturnType<typeof and>) => {
    const row = await db.select().from(invitations).where(condition).get();
    return row === undefined ? null : toInvitationRecord(row);
  };
  /**
   * The INSERT…SELECT of an invite.* audit row (AUDIT_SPEC §3.2 /
   * §5.2). Inserted only when the immediately preceding conditional
   * UPDATE hit 1 row (the changes() guard). The FROM is the target
   * invitation row itself (project_id is copied from the stored row —
   * never composed from a wire-declared value). org_id is not carried:
   * invite.*'s read axis is chain role admin, not org admin (AUDIT_SPEC
   * §7).
   */
  const guardedAuditInsert = (input: {
    readonly inviteId: string;
    readonly event: "invite.created" | "invite.accepted" | "invite.revoked";
    readonly actor: D1AuditActor;
    readonly targetUserId: string | null;
    readonly payload: Readonly<Record<string, unknown>>;
    readonly nowMs: number;
  }) =>
    db.insert(orgAuditEvents).select(
      db
        .select({
          // The shared columns (audit.ts — the same mapping as
          // recovery's fetch counting) + project_id copied from the
          // target invitation row (never composed from a wire-declared
          // value)
          ...guardedAuditSelectColumns(input),
          projectId: invitations.projectId,
        })
        .from(invitations)
        .where(and(eq(invitations.id, input.inviteId), sql`changes() = 1`)),
    );
  return {
    create: (input, nowMs, actor) =>
      run(async () => {
        // The judgment and the insert are folded into a single
        // INSERT…SELECT. With a separate request's SELECT → INSERT,
        // every concurrent issuer would observe the same under-limit
        // and could exceed the cap by the degree of parallelism. The
        // audit is written under the changes() guard only when the
        // immediately preceding INSERT hit 1 row
        // A duplicate of a client-sequenced id / link_pub is a 409
        // (ahead of the acceptance policy — §15-2's judgment order). A
        // random-derived collision is effectively impossible, but a
        // reused id is never silently let through. It is detected
        // deterministically by a prior SELECT, and a concurrent
        // issuance interposing between the SELECT and the INSERT
        // surfaces as a UNIQUE constraint error and is mapped to the
        // same 409
        const existing = await db
          .select({ id: invitations.id, linkPub: invitations.linkPub })
          .from(invitations)
          .where(
            or(eq(invitations.id, input.id), eq(invitations.linkPub, input.issuance.linkPubHex)),
          )
          .limit(1);
        const found = existing[0];
        if (found !== undefined) {
          return { kind: "conflict", field: found.id === input.id ? "id" : "linkPub" } as const;
        }
        const insert = () =>
          db.batch([
            conditionalInviteInsert(db, input, nowMs),
            guardedAuditInsert({
              inviteId: input.id,
              event: "invite.created",
              actor,
              targetUserId: null,
              payload: { inviteId: input.id, role: input.role },
              nowMs,
            }),
          ]);
        let results: Awaited<ReturnType<typeof insert>>;
        try {
          results = await insert();
        } catch (error) {
          const conflict = inviteUniqueConflictOf(error);
          if (conflict !== null) {
            return { kind: "conflict", field: conflict } as const;
          }
          throw error;
        }
        if (results[0].length === 1) {
          return { kind: "created" } as const;
        }
        const rejection = await inviteIssueRejection(db, input.projectId, nowMs);
        if (rejection !== null) {
          return rejection;
        }
        // A rare race where revoke / expiry progressed between the
        // conditional INSERT and the explaining re-read and admission
        // momentarily became possible again. Falls to a typed
        // rate-limit that a fresh request can safely retry; never
        // falls back to breaking the cap
        return {
          kind: "rate-limited",
          retryAfterSeconds: 1,
        } as const;
      }),
    findByLinkPub: (linkPubHex) => run(() => findWhere(eq(invitations.linkPub, linkPubHex))),
    findById: (projectId, id) =>
      run(() => findWhere(and(eq(invitations.id, id), eq(invitations.projectId, projectId)))),
    listForProject: (projectId) =>
      run(async () => {
        const rows = await db
          .select()
          .from(invitations)
          .where(eq(invitations.projectId, projectId))
          .orderBy(invitations.createdAt, invitations.id);
        return rows.map(toInvitationRecord);
      }),
    acceptCas: (input, nowMs, actor) =>
      run(async () => {
        const results = await db.batch([
          db
            .update(invitations)
            .set({
              status: "accepted",
              inviteeUserId: input.inviteeUserId,
              inviteeEncPub: input.inviteeEncPubHex,
              inviteeSigPub: input.inviteeSigPubHex,
              acceptSignature: input.acceptSignatureHex,
              linkSignature: input.linkSignatureHex,
              acceptedAt: nowMs,
            })
            .where(
              and(
                eq(invitations.id, input.inviteId),
                eq(invitations.status, "pending"),
                gt(invitations.expiresAt, nowMs),
              ),
            )
            .returning({ id: invitations.id }),
          guardedAuditInsert({
            inviteId: input.inviteId,
            event: "invite.accepted",
            actor,
            targetUserId: input.inviteeUserId,
            payload: {
              inviteId: input.inviteId,
              inviteeKeyFingerprintHex: input.inviteeKeyFingerprintHex,
            },
            nowMs,
          }),
        ]);
        return results[0].length === 1;
      }),
    revokeCas: (projectId, id, payload, nowMs, actor) =>
      run(async () => {
        const results = await db.batch([
          db
            .update(invitations)
            .set({ status: "revoked" })
            .where(
              and(
                eq(invitations.id, id),
                eq(invitations.projectId, projectId),
                inArray(invitations.status, ["pending", "accepted"]),
              ),
            )
            .returning({ id: invitations.id }),
          guardedAuditInsert({
            inviteId: id,
            event: "invite.revoked",
            actor,
            targetUserId: null,
            payload: { inviteId: id, role: payload.role },
            nowMs,
          }),
        ]);
        return results[0].length === 1;
      }),
    completeAccepted: (target) =>
      run(async () => {
        await db
          .update(invitations)
          .set({ status: "completed" })
          .where(
            and(
              eq(invitations.projectId, target.projectId),
              eq(invitations.inviteeUserId, target.inviteeUserId),
              eq(invitations.status, "accepted"),
              eq(invitations.inviteeEncPub, target.inviteeEncPubHex),
              eq(invitations.inviteeSigPub, target.inviteeSigPubHex),
            ),
          );
      }),
  };
}

// ---------------------------------------------------------------------------
// FlowSigningKeyRepo (AUTH_SPEC §4-2. The store of the CLI login flow
// signing key)
// ---------------------------------------------------------------------------

/** The fixed id of the signing-key row (at most one row). */
const FLOW_SIGNING_KEY_ID = "v1";

interface FlowSigningKeyRepoShape {
  /**
   * Auto-generation on first use (AUTH_SPEC §4-2 — does not add to the
   * self-host setup steps). Idempotent, first-one-wins: the candidate
   * key is INSERT OR IGNOREd and the stored row is always read back —
   * closing the branch where two simultaneous first-use requests write
   * different keys and invalidate an in-flight flow. The return value
   * is the winning key (hex).
   */
  readonly getOrCreate: (candidateKeyHex: string, nowMs: number) => Effect.Effect<string>;
}

export class FlowSigningKeyRepo extends Context.Service<
  FlowSigningKeyRepo,
  FlowSigningKeyRepoShape
>()("FlowSigningKeyRepo") {}

function makeFlowSigningKeyRepo(db: Db): FlowSigningKeyRepoShape {
  return {
    getOrCreate: (candidateKeyHex, nowMs) =>
      run(async () => {
        await db
          .insert(flowSigningKeys)
          .values({ id: FLOW_SIGNING_KEY_ID, keyHex: candidateKeyHex, createdAt: nowMs })
          .onConflictDoNothing();
        const row = await db
          .select({ keyHex: flowSigningKeys.keyHex })
          .from(flowSigningKeys)
          .where(eq(flowSigningKeys.id, FLOW_SIGNING_KEY_ID))
          .get();
        if (row === undefined) {
          // An empty SELECT right after the INSERT OR IGNORE = a D1 failure (defect)
          throw new Error("flow signing key insert succeeded but the row is missing");
        }
        return row.keyHex;
      }),
  };
}

// ---------------------------------------------------------------------------
// CliFlowRepo (AUTH_SPEC §4-1 (4)–(5). The CLI login flow rows)
// ---------------------------------------------------------------------------

/**
 * The cap on concurrent unconsumed flow rows across the whole
 * deployment (the AUTH_SPEC §4-1 (4) (iii) drafted value). Reaching it
 * requires the cap's worth of simultaneous "existing account × OAuth
 * completion" runs, so it cannot be held cheaply. Recovers naturally
 * with the 15-minute TTL. Adjustable as a self-host acceptance policy.
 */
export const MAX_CONCURRENT_CLI_FLOWS = 1000;

/**
 * The headroom for keeping a row past its expiry (the AUTH_SPEC §4-1
 * (5) drafted value +5 minutes). Deleting a consumed / denied row
 * before the flowToken's expiry would let a poll misread "no row =
 * pending" and the CLI would wait forever on a completed flow.
 * Opportunistic deletion targets only rows past this headroom.
 */
const CLI_FLOW_DELETE_GRACE_MS = 5 * 60 * 1000;

/** The state of a flow row (the CAS vocabulary of §4-1 (4)–(5)). */
type CliFlowStatus = "awaiting" | "approved" | "denied" | "consumed";

/** The explicit operation on the approval page (§4-1 (4) (iv) — the two choices: approve / deny). */
type CliFlowDecision = "approved" | "denied";

interface NewCliLoginFlow {
  readonly flowId: string;
  readonly userId: string;
  readonly tokenName: string;
  readonly scopes: readonly TokenScope[];
  readonly expiresInDays: number;
  readonly userCode: string;
  /** The SHA-256 (hex) of the approval ticket (a 256-bit random). The raw value lives only on the page. */
  readonly ticketHash: string;
  readonly expiresAtMs: number;
}

/** The shape the poll's row lookup (§4-1 (5)) sees. ticket_hash is excluded (the comparison happens inside the CAS). */
interface CliLoginFlowRecord {
  readonly flowId: string;
  readonly userId: string;
  readonly status: CliFlowStatus;
  readonly tokenName: string;
  readonly scopes: readonly TokenScope[];
  readonly expiresInDays: number;
  readonly userCode: string;
  readonly expiresAtMs: number;
}

/**
 * The outcome of create-or-match (§4-1 (4) (iii)). created / matched
 * proceed to rendering the approval page. rejected is the uniform
 * error page (another user_id, expired, or a terminal state — the
 * reason is not differentiated); capacity is the cap reached (the same
 * uniform error page + the input of an operational alert).
 */
type CliFlowAdmission = "created" | "matched" | "rejected" | "capacity";

interface CliFlowRepoShape {
  /**
   * The creation CAS of a flow row (create-or-match — §4-1 (4) (iii)).
   * An opportunistic delete of rows past expiry + headroom is bundled
   * at the batch's head, and creation is done by a conditional INSERT
   * on "no row with the same flowId × the unconsumed total under the
   * cap". When the row already exists, only a re-arrival with the same
   * user_id × awaiting × within validity succeeds by replacing the
   * ticket (idempotent — matched). A different user_id is rejected
   * without rotating the ticket (closing both the takeover and the
   * ticket-invalidation attack paths).
   */
  readonly createOrMatch: (flow: NewCliLoginFlow, nowMs: number) => Effect.Effect<CliFlowAdmission>;
  /**
   * The approve / deny CAS (awaiting → approved | denied — §4-1 (4)
   * (iv)). The credential is the approval ticket (the latest one);
   * unknown, expired, and used all uniformly return false. An approval
   * (user_id settled) records `auth.login_succeeded` (authMethod
   * cli_handoff — §4-2) in the same batch under the changes() guard.
   */
  readonly decideCas: (
    flowId: string,
    ticketHash: string,
    decision: CliFlowDecision,
    nowMs: number,
  ) => Effect.Effect<boolean>;
  /** The poll's row lookup (§4-1 (5)). No row = null (the caller derives pending). */
  readonly findById: (flowId: string) => Effect.Effect<CliLoginFlowRecord | null>;
  /**
   * The single-issuance gate (the approved → consumed CAS — §4-1 (5)).
   * Only the winner (true) issues a PAT. An issuance failure after the
   * CAS succeeded ends consumed as-is (fail-closed — the caller does
   * not roll back).
   */
  readonly consumeCas: (flowId: string) => Effect.Effect<boolean>;
}

export class CliFlowRepo extends Context.Service<CliFlowRepo, CliFlowRepoShape>()("CliFlowRepo") {}

function makeCliFlowRepo(db: Db): CliFlowRepoShape {
  return {
    createOrMatch: (flow, nowMs) =>
      run(async () => {
        // The cap is counted on unconsumed rows (anything but consumed)
        // (§4-1 (4) (iii)'s "concurrent unconsumed rows"). The judgment
        // and the insert are the same INSERT…SELECT (same shape as the
        // invites admission — a concurrent creation never observes the
        // same under-limit and exceeds the cap)
        const capAvailable = sql<boolean>`(
          select count(*) from ${cliLoginFlows}
          where ${cliLoginFlows.status} != 'consumed'
        ) < ${MAX_CONCURRENT_CLI_FLOWS}`;
        const rowAbsent = sql<boolean>`not exists (
          select 1 from ${cliLoginFlows} where ${cliLoginFlows.id} = ${flow.flowId}
        )`;
        const results = await db.batch([
          // The opportunistic delete (§4-1 (4) (iii)): only rows past
          // expiry + headroom. consumed / denied rows are also kept
          // within the headroom (blocking a poll's "no row = pending"
          // misread)
          db
            .delete(cliLoginFlows)
            .where(lte(cliLoginFlows.expiresAt, nowMs - CLI_FLOW_DELETE_GRACE_MS)),
          db
            .insert(cliLoginFlows)
            .select(
              db
                .select({
                  id: sql<string>`${flow.flowId}`.as("id"),
                  userId: sql<string>`${flow.userId}`.as("user_id"),
                  status: sql<string>`'awaiting'`.as("status"),
                  tokenName: sql<string>`${flow.tokenName}`.as("token_name"),
                  scopes: sql<string>`${JSON.stringify(flow.scopes)}`.as("scopes"),
                  expiresInDays: sql<number>`${flow.expiresInDays}`.as("expires_in_days"),
                  userCode: sql<string>`${flow.userCode}`.as("user_code"),
                  ticketHash: sql<string>`${flow.ticketHash}`.as("ticket_hash"),
                  expiresAt: sql<number>`${flow.expiresAtMs}`.as("expires_at"),
                  createdAt: sql<number>`${nowMs}`.as("created_at"),
                })
                .from(sql`(select 1)`)
                .where(and(capAvailable, rowAbsent)),
            )
            .returning({ id: cliLoginFlows.id }),
        ]);
        if (results[1].length === 1) {
          return "created";
        }
        // Either the row exists (match / conflict) or the cap was hit.
        // Only a re-arrival with the same user_id × awaiting × within
        // validity succeeds by replacing the ticket (the old ticket is
        // revoked by the replacement — at any time exactly one latest
        // ticket is valid). A different user_id never matches this
        // UPDATE = the ticket is not rotated (§4-1 (4) (iii))
        const matched = await db
          .update(cliLoginFlows)
          .set({ ticketHash: flow.ticketHash })
          .where(
            and(
              eq(cliLoginFlows.id, flow.flowId),
              eq(cliLoginFlows.userId, flow.userId),
              eq(cliLoginFlows.status, "awaiting"),
              gt(cliLoginFlows.expiresAt, nowMs),
            ),
          )
          .returning({ id: cliLoginFlows.id });
        if (matched.length === 1) {
          return "matched";
        }
        const existing = await db
          .select({ id: cliLoginFlows.id })
          .from(cliLoginFlows)
          .where(eq(cliLoginFlows.id, flow.flowId))
          .get();
        // No row = what dropped the conditional INSERT was the cap
        // (capacity). A row = another user_id / expired / a terminal
        // state (uniformly rejected — never differentiated)
        return existing === undefined ? "capacity" : "rejected";
      }),
    decideCas: (flowId, ticketHash, decision, nowMs) =>
      run(async () => {
        const cas = db
          .update(cliLoginFlows)
          .set({ status: decision })
          .where(
            and(
              eq(cliLoginFlows.id, flowId),
              eq(cliLoginFlows.status, "awaiting"),
              eq(cliLoginFlows.ticketHash, ticketHash),
              gt(cliLoginFlows.expiresAt, nowMs),
            ),
          )
          .returning({ id: cliLoginFlows.id });
        if (decision !== "approved") {
          // A denial carries no audit event (§4-2 — only an approval =
          // login_succeeded. The failure family follows login_failed's
          // fixed-window discipline, and an explicit denial is neither)
          return (await cas).length === 1;
        }
        // An approval = auth.login_succeeded (authMethod cli_handoff —
        // §4-2). The actor's user_id is copied from the row (the
        // changes() guard — same shape as the invites CAS)
        const results = await db.batch([
          cas,
          db.insert(userAuditEvents).select(
            db
              .select({
                ...guardedAuditSelectColumns({
                  event: "auth.login_succeeded",
                  actor: { authMethod: "cli_handoff" },
                  nowMs,
                  payload: { flowId },
                }),
                actorUserId: cliLoginFlows.userId,
              })
              .from(cliLoginFlows)
              .where(and(eq(cliLoginFlows.id, flowId), sql`changes() = 1`)),
          ),
        ]);
        return results[0].length === 1;
      }),
    findById: (flowId) =>
      run(async () => {
        const row = await db
          .select({
            id: cliLoginFlows.id,
            userId: cliLoginFlows.userId,
            status: cliLoginFlows.status,
            tokenName: cliLoginFlows.tokenName,
            scopes: cliLoginFlows.scopes,
            expiresInDays: cliLoginFlows.expiresInDays,
            userCode: cliLoginFlows.userCode,
            expiresAt: cliLoginFlows.expiresAt,
          })
          .from(cliLoginFlows)
          .where(eq(cliLoginFlows.id, flowId))
          .get();
        if (row === undefined) {
          return null;
        }
        const scopes = parseTokenScopes(row.scopes);
        if (scopes === null) {
          // A column only our own write path can produce being broken =
          // an implementation bug / DB corruption
          throw new Error("stored CLI flow scopes are not a valid scope array");
        }
        return {
          flowId: row.id,
          userId: row.userId,
          status: row.status as CliFlowStatus,
          tokenName: row.tokenName,
          scopes,
          expiresInDays: row.expiresInDays,
          userCode: row.userCode,
          expiresAtMs: row.expiresAt,
        };
      }),
    consumeCas: (flowId) =>
      run(async () => {
        const rows = await db
          .update(cliLoginFlows)
          .set({ status: "consumed" })
          .where(and(eq(cliLoginFlows.id, flowId), eq(cliLoginFlows.status, "approved")))
          .returning({ id: cliLoginFlows.id });
        return rows.length === 1;
      }),
  };
}

// ---------------------------------------------------------------------------
// The bundle: build the Context of the whole repository set from a D1
// binding
// ---------------------------------------------------------------------------

export type DbServices =
  | IdentityRepo
  | SessionRepo
  | TokenRepo
  | OrgRepo
  | ProjectRepo
  | RecoveryRepo
  | InviteRepo
  | FlowSigningKeyRepo
  | CliFlowRepo
  | D1AuditRepo
  | OpsRepo
  | KeyWrapRepo
  | DeviceRepo;

/** Builds the set of repository services from a D1 binding (once at worker startup). */
export function makeDbServices(d1: D1Database): Context.Context<DbServices> {
  const db = drizzle(d1);
  // The master key-wrap ledger (AUTH_SPEC §13-6–13-10 — KL3). The
  // recovery-code fetch window also uses this summed window (§13-8)
  const keyWraps = makeKeyWrapRepo(db);
  return Context.make(IdentityRepo, makeIdentityRepo(db)).pipe(
    Context.add(SessionRepo, makeSessionRepo(db)),
    Context.add(TokenRepo, makeTokenRepo(db)),
    Context.add(OrgRepo, makeOrgRepo(db)),
    Context.add(ProjectRepo, makeProjectRepo(db)),
    Context.add(RecoveryRepo, makeRecoveryRepo(db, keyWraps)),
    Context.add(KeyWrapRepo, keyWraps),
    Context.add(InviteRepo, makeInviteRepo(db)),
    Context.add(FlowSigningKeyRepo, makeFlowSigningKeyRepo(db)),
    Context.add(CliFlowRepo, makeCliFlowRepo(db)),
    Context.add(D1AuditRepo, makeD1AuditRepo(db)),
    // Operations (H3 — hosted-ops.md §6): counters, evacuation
    // records, state kv
    Context.add(OpsRepo, makeOpsRepo(db)),
    // The device registry and device-add requests (AUTH_SPEC §13-11 —
    // DK K3. advisory)
    Context.add(DeviceRepo, makeDeviceRepo(db)),
  );
}
