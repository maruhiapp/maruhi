import type { SignupPolicy } from "@maruhi/api-schema";
import type { OrgId, OrgRole, ProviderUserId, UserId } from "@maruhi/core";
import { and, eq, gt, inArray, isNull, sql, type SQL } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Data, Effect, Ref } from "effect";
import { SecureRandom } from "effect/crypto";

import type { ResolvedUser, SignupGateResult, UserOrg, VerifiedIdentity } from "../auth-domain.ts";
import { newOrgId, newUserId } from "../ids.ts";
import { type D1AuditActor, guardedAuditSelectColumns } from "./audit.ts";
import { type D1Error, type D1FailureError, tryD1 } from "./errors.ts";
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

interface IdentityRepoShape {
  readonly getOrCreateUser: (
    identity: VerifiedIdentity,
    nowMs: number,
    signupInviteTokenHash: string | null,
  ) => Effect.Effect<SignupGateResult, never, SecureRandom.SecureRandom>;
  readonly lookupUser: (identity: VerifiedIdentity) => Effect.Effect<UserId | null>;
  readonly listUserOrgs: (userId: UserId) => Effect.Effect<readonly UserOrg[]>;
  readonly providerLoginOf: (userId: UserId) => Effect.Effect<string | null>;
  readonly identitiesOf: (
    userIds: readonly UserId[],
  ) => Effect.Effect<readonly LinkedIdentityRecord[]>;
  readonly signupPolicy: Effect.Effect<SignupPolicy>;
  readonly hasPendingSignupInvite: (tokenHashHex: string, nowMs: number) => Effect.Effect<boolean>;
}

export class IdentityRepo extends Context.Service<IdentityRepo, IdentityRepoShape>()(
  "IdentityRepo",
) {}

interface LinkedIdentityRecord {
  readonly userId: UserId;
  readonly provider: "github";
  readonly providerUserId: ProviderUserId;
  readonly providerLogin: string | null;
}

const IDENTITY_IN_CHUNK = 90;

function identitiesOf(
  db: Db,
  userIds: readonly UserId[],
): Effect.Effect<readonly LinkedIdentityRecord[], D1Error> {
  return tryD1(async () => {
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

function lookupLinkedUser(
  db: Db,
  identity: VerifiedIdentity,
): Effect.Effect<UserId | null, D1Error> {
  return tryD1(async () => {
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
const SIGNUP_POLICY_KEY = "signup_policy";

const readSignupPolicy = Effect.fn("identities.readSignupPolicy")(function* (
  db: Db,
  warnedUnknownSignupPolicy: Ref.Ref<boolean>,
): Effect.fn.Return<SignupPolicy, D1Error> {
  const row = yield* tryD1(() =>
    db
      .select({ value: deploymentSettings.value })
      .from(deploymentSettings)
      .where(eq(deploymentSettings.key, SIGNUP_POLICY_KEY))
      .get(),
  );
  if (row === undefined) {
    return "open";
  }
  if (row.value === "open" || row.value === "invite" || row.value === "closed") {
    return row.value;
  }
  if (!(yield* Ref.getAndSet(warnedUnknownSignupPolicy, true))) {
    yield* Effect.logWarning(
      "deployment_settings.signup_policy has an unknown value; treating it as 'closed' (fail-closed — fix it with the SQL in docs/SELF_HOSTING.md)",
    );
  }
  return "closed";
});

function signupPolicyIs(value: SignupPolicy): SQL {
  return sql`(select coalesce((select ${deploymentSettings.value} from ${deploymentSettings} where ${deploymentSettings.key} = ${SIGNUP_POLICY_KEY}), 'open')) = ${value}`;
}

type SignupGate =
  | { readonly kind: "open" }
  | { readonly kind: "invite"; readonly inviteId: string };

class SignupGateLostError extends Data.TaggedError("SignupGateLost")<object> {}

function createUserBatch(
  db: Db,
  identity: VerifiedIdentity,
  nowMs: number,
  gate: SignupGate,
): Effect.Effect<
  UserId,
  InsertConflictError | SignupGateLostError | D1FailureError,
  SecureRandom.SecureRandom
> {
  return Effect.flatMap(newUserId(nowMs), (userId) =>
    Effect.map(newOrgId(nowMs), (orgId) => ({ userId, orgId })),
  ).pipe(
    Effect.flatMap(({ userId, orgId }) =>
      createUserBatchWithIds(db, identity, nowMs, gate, userId, orgId),
    ),
  );
}

function createUserBatchWithIds(
  db: Db,
  identity: VerifiedIdentity,
  nowMs: number,
  gate: SignupGate,
  userId: UserId,
  orgId: OrgId,
): Effect.Effect<UserId, InsertConflictError | SignupGateLostError | D1FailureError> {
  const actor: D1AuditActor = { userId };
  const chained = sql`changes() = 1`;
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
  return tryD1(async () => {
    const createdRows =
      gate.kind === "invite"
        ? (
            await db.batch([
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
  }).pipe(
    Effect.catchTag("D1UniqueConflict", () => Effect.fail(new InsertConflictError())),
    Effect.flatMap((created) =>
      created === null ? Effect.fail(new SignupGateLostError()) : Effect.succeed(created),
    ),
  );
}

function refreshVerifiedEmail(
  db: Db,
  userId: UserId,
  identity: VerifiedIdentity,
  nowMs: number,
): Effect.Effect<void, D1Error> {
  if (identity.verifiedEmail === null) {
    return Effect.void;
  }
  const email = identity.verifiedEmail;
  return tryD1(async () => {
    await db
      .update(users)
      .set({ email, emailVerified: 1, updatedAt: nowMs })
      .where(and(eq(users.id, userId), isNull(users.email)));
  });
}

function findPendingSignupInvite(
  db: Db,
  tokenHashHex: string,
  nowMs: number,
): Effect.Effect<{ readonly id: string } | null, D1Error> {
  return tryD1(async () => {
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
  const warnedUnknownSignupPolicy = Ref.makeUnsafe(false);

  const getOrCreateUser = (
    identity: VerifiedIdentity,
    nowMs: number,
    signupInviteTokenHash: string | null,
    attempt = 0,
  ): Effect.Effect<SignupGateResult, D1Error, SecureRandom.SecureRandom> => {
    const attemptCreate = (
      gate: SignupGate,
    ): Effect.Effect<SignupGateResult, D1Error, SecureRandom.SecureRandom> =>
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
        return Effect.as(refreshVerifiedEmail(db, existing, identity, nowMs), {
          userId: existing,
          created: false,
        } satisfies ResolvedUser);
      }
      return Effect.flatMap(readSignupPolicy(db, warnedUnknownSignupPolicy), (policy) => {
        if (policy === "closed") {
          return Effect.succeed<SignupGateResult>({ denied: "policy-closed" });
        }
        if (policy === "open") {
          return attemptCreate({ kind: "open" });
        }
        if (signupInviteTokenHash === null) {
          return Effect.succeed<SignupGateResult>({ denied: "invite-required" });
        }
        return Effect.flatMap(findPendingSignupInvite(db, signupInviteTokenHash, nowMs), (invite) =>
          invite === null
            ? Effect.succeed<SignupGateResult>({ denied: "invite-invalid" })
            : attemptCreate({ kind: "invite", inviteId: invite.id }),
        );
      });
    });
  };
  return {
    getOrCreateUser: (identity, nowMs, signupInviteTokenHash) =>
      getOrCreateUser(identity, nowMs, signupInviteTokenHash).pipe(Effect.orDie),
    lookupUser: (identity) => lookupLinkedUser(db, identity).pipe(Effect.orDie),
    listUserOrgs: (userId) => listUserOrgs(db, userId).pipe(Effect.orDie),
    providerLoginOf: (userId) => providerLoginOf(db, userId).pipe(Effect.orDie),
    identitiesOf: (userIds) => identitiesOf(db, userIds).pipe(Effect.orDie),
    signupPolicy: readSignupPolicy(db, warnedUnknownSignupPolicy).pipe(Effect.orDie),
    hasPendingSignupInvite: (tokenHashHex, nowMs) =>
      findPendingSignupInvite(db, tokenHashHex, nowMs).pipe(
        Effect.map((row) => row !== null),
        Effect.orDie,
      ),
  };
}

function rerunLookup(db: Db, identity: VerifiedIdentity): Effect.Effect<ResolvedUser, D1Error> {
  return Effect.flatMap(lookupLinkedUser(db, identity), (found) =>
    found === null
      ? Effect.die(new Error("linked identity insert failed without a conflicting row"))
      : Effect.succeed({ userId: found, created: false }),
  );
}

function providerLoginOf(db: Db, userId: UserId): Effect.Effect<string | null, D1Error> {
  return tryD1(async () => {
    const row = await db
      .select({ login: linkedIdentities.providerLogin })
      .from(linkedIdentities)
      .where(and(eq(linkedIdentities.userId, userId), eq(linkedIdentities.provider, "github")))
      .get();
    return row?.login ?? null;
  });
}

function listUserOrgs(db: Db, userId: UserId): Effect.Effect<readonly UserOrg[], D1Error> {
  return tryD1(async () => {
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
