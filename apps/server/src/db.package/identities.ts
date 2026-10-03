// Repository of the identity ledger: users, linked provider identities,
// the automatic personal org, and the signupPolicy gate (AUTH_SPEC
// §1–§3, §9-1).

import type { SignupPolicy } from "@maruhi/api-schema";
import type { OrgRole } from "@maruhi/core";
import { and, eq, gt, inArray, isNull, sql, type SQL } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Data, Effect } from "effect";

import type { ResolvedUser, SignupGateResult, UserOrg, VerifiedIdentity } from "../auth-domain.ts";
import { ulid } from "../ids.ts";
import { type D1AuditActor, guardedAuditSelectColumns } from "./audit.ts";
import { isUniqueConflict } from "./errors.ts";
import {
  deploymentSettings,
  linkedIdentities,
  memberships,
  organizations,
  orgAuditEvents,
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
   * The linked GitHub identities of the given users (the identities
   * companion of a project export — AUTH_SPEC §11-6, PF3). Users without
   * a link are absent from the result (never invented).
   */
  readonly identitiesOf: (
    userIds: readonly string[],
  ) => Effect.Effect<readonly LinkedIdentityRecord[]>;
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

/** One linked provider identity as the export carries it (AUTH_SPEC §2's lookup key plus the display login). */
interface LinkedIdentityRecord {
  readonly userId: string;
  readonly provider: "github";
  readonly providerUserId: string;
  readonly providerLogin: string | null;
}

/** The IN chunk of identitiesOf (inside D1's bound-parameter cap with headroom). */
const IDENTITY_IN_CHUNK = 90;

function identitiesOf(
  db: Db,
  userIds: readonly string[],
): Effect.Effect<readonly LinkedIdentityRecord[]> {
  return run(async () => {
    const rows: LinkedIdentityRecord[] = [];
    for (let start = 0; start < userIds.length; start += IDENTITY_IN_CHUNK) {
      const chunk = userIds.slice(start, start + IDENTITY_IN_CHUNK);
      const found = await db
        .select({
          userId: linkedIdentities.userId,
          providerUserId: linkedIdentities.providerUserId,
          providerLogin: linkedIdentities.providerLogin,
        })
        .from(linkedIdentities)
        .where(
          and(eq(linkedIdentities.provider, "github"), inArray(linkedIdentities.userId, chunk)),
        );
      rows.push(...found.map((row) => ({ ...row, provider: "github" as const })));
    }
    return rows.toSorted((a, b) => (a.userId < b.userId ? -1 : a.userId > b.userId ? 1 : 0));
  });
}

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

export function makeIdentityRepo(db: Db): IdentityRepoShape {
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
    identitiesOf: (userIds) => identitiesOf(db, userIds),
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
