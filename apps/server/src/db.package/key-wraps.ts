// Repository of the master-key wrap ledger (AUTH_SPEC §13-6–13-10 — KL3).
//
// - Drizzle types and queries stay inside this file (within the
//   db.package boundary). The public shapes are the domain types in
//   ../key-wrap-domain.ts and Effect only
// - Audit (the 9 KL3 events of AUDIT_SPEC §3.1) is recorded in the same
//   batch as the record operation. Rejections (429 / 404 / 409 / 422)
//   are not recorded (what was not accepted is not recorded — §13-10)
// - The §13-8 fixed windows are counted by **a single conditional
//   UPSERT** on `key_wrap_windows` (user × kind) (same design as
//   RecoveryRepo.recordFetch: a two-stage read → write lets concurrent
//   requests read the same count and counting stalls). Allowance =
//   RETURNING yields 1 row; audit is bundled 1:1 with allowance via an
//   INSERT…SELECT guarded by `changes() = 1`
// - Wraps and segments are opaque to the server; this file does not
//   interpret their contents

import { and, count, eq, inArray, isNull, lte, sql } from "drizzle-orm";
import type { SQL } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import type { SQLiteTable } from "drizzle-orm/sqlite-core";
import { Context, Effect } from "effect";

import type {
  GuardianGroupRecord,
  GuardianMode,
  GuardianShareRecord,
  HandoffApprovalRecord,
  HandoffRequestRecord,
  KeyWrapWindowDecision,
  KeyWrapWindowKind,
  MasterKeyWrapBlob,
  PasskeyWrapRecord,
  WardShareRecord,
} from "../key-wrap-domain.ts";
import { type D1AuditActor, type D1AuditEventInput, guardedAuditSelectColumns } from "./audit.ts";
import {
  guardianGroups,
  guardianShares,
  keyHandoffApprovals,
  keyHandoffRequests,
  keyWrapWindows,
  linkedIdentities,
  masterKeyWraps,
  userAuditEvents,
  users,
} from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

/** D1 failures are defects (Effect.promise). Only domain-level branches are returned as values. */
const run = <A>(thunk: () => Promise<A>): Effect.Effect<A> => Effect.promise(thunk);

/** The §13-8 fixed-window length (all 1 hour). */
const KEY_WRAP_WINDOW_MS = 60 * 60 * 1000;
/** Aggregate cap for blob fetches (§13-8 — §13-3's 5 per hour, reinterpreted as summed over kinds). */
export const KEY_BLOB_FETCH_LIMIT = 5;
/** Handoff-request cap (§13-8: 5 per hour per ward). */
export const HANDOFF_REQUEST_LIMIT = 5;
/** Approval-window cap (§13-8: 20 segment fetches + approvals per hour per approver). */
export const APPROVAL_LIMIT = 20;

/** Grace before opportunistic deletion of expired requests (rows more than 1 hour past expiry are deleted). */
const HANDOFF_SWEEP_GRACE_MS = 60 * 60 * 1000;

export interface GuardianShareInput {
  readonly shareIndex: number;
  readonly guardianUserId: string;
  readonly guardianEncPubHex: string;
  readonly guardianKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

export interface HandoffApprovalInput {
  readonly source: string;
  readonly shareIndex: number;
  readonly approverKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}

export interface KeyWrapRepoShape {
  // --- Fixed windows (§13-8)----------------------------------------------
  /**
   * Consumes one window. When `audit` is given, it is recorded in the
   * same batch only on allowance (rejections are not recorded). A path
   * that bundles the record with another insert, like approvals, omits
   * this.
   */
  readonly consumeWindow: (input: {
    readonly userId: string;
    readonly kind: KeyWrapWindowKind;
    readonly limit: number;
    readonly nowMs: number;
    readonly audit?: D1AuditEventInput;
  }) => Effect.Effect<KeyWrapWindowDecision>;
  /** Window reset (recovery-code reissue — a new blob does not inherit the attempt history against the old one). */
  readonly resetWindow: (userId: string, kind: KeyWrapWindowKind) => Effect.Effect<void>;

  // --- Class S (passkey-prf)------------------------------------------------
  readonly passkeyInsert: (input: {
    readonly userId: string;
    readonly wrapId: string;
    readonly params: string;
    readonly wrap: MasterKeyWrapBlob;
    readonly limit: number;
    readonly nowMs: number;
    readonly actor: D1AuditActor;
  }) => Effect.Effect<"created" | "limit" | "conflict">;
  readonly passkeyFind: (userId: string, wrapId: string) => Effect.Effect<PasskeyWrapRecord | null>;
  readonly passkeyList: (userId: string) => Effect.Effect<readonly PasskeyWrapRecord[]>;
  readonly passkeyDelete: (
    userId: string,
    wrapId: string,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<boolean>;

  // --- Class G (guardian groups)-------------------------------------------
  /** Returns the user_ids that do not exist (guardian existence check). */
  readonly missingUsers: (userIds: readonly string[]) => Effect.Effect<readonly string[]>;
  readonly guardianCreate: (input: {
    readonly userId: string;
    readonly groupId: string;
    readonly mode: GuardianMode;
    readonly wrap: MasterKeyWrapBlob;
    readonly shares: readonly GuardianShareInput[];
    readonly limit: number;
    readonly nowMs: number;
    readonly actor: D1AuditActor;
  }) => Effect.Effect<"created" | "limit" | "conflict">;
  readonly guardianFind: (
    userId: string,
    groupId: string,
  ) => Effect.Effect<GuardianGroupRecord | null>;
  readonly guardianList: (userId: string) => Effect.Effect<readonly GuardianGroupRecord[]>;
  readonly guardianDelete: (
    userId: string,
    groupId: string,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<boolean>;
  /** The guardian's own segments as the guardian sees them (optionally narrowed by ward). */
  readonly sharesOfGuardian: (
    guardianUserId: string,
    wardUserId?: string,
  ) => Effect.Effect<readonly WardShareRecord[]>;

  // --- Class H (handoff)----------------------------------------------------
  readonly handoffCreate: (input: {
    readonly requestId: string;
    readonly userId: string;
    readonly ttlMs: number;
    readonly nowMs: number;
    readonly actor: D1AuditActor;
  }) => Effect.Effect<"created" | "conflict">;
  /** Returns only requests that have not expired. */
  readonly handoffFind: (
    requestId: string,
    nowMs: number,
  ) => Effect.Effect<HandoffRequestRecord | null>;
  readonly handoffApprove: (input: {
    readonly requestId: string;
    readonly wardUserId: string;
    readonly approverUserId: string;
    readonly approval: HandoffApprovalInput;
    readonly limit: number;
    readonly nowMs: number;
    readonly actor: D1AuditActor;
  }) => Effect.Effect<"created" | "conflict" | "exceeded">;
  readonly handoffApprovals: (requestId: string) => Effect.Effect<readonly HandoffApprovalRecord[]>;
  /** Records the first fetch (1 or more) exactly once as auth.key_handoff_collected. */
  readonly handoffMarkCollected: (
    requestId: string,
    approvalCount: number,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<void>;
  readonly handoffDelete: (requestId: string, userId: string) => Effect.Effect<boolean>;
  /** Opportunistic deletion of requests past expiry + grace (approvals are removed by cascade). */
  readonly handoffSweep: (nowMs: number) => Effect.Effect<void>;
  /** The login snapshot for display (github). */
  readonly loginOf: (userId: string) => Effect.Effect<string | null>;
}

export class KeyWrapRepo extends Context.Service<KeyWrapRepo, KeyWrapRepoShape>()("KeyWrapRepo") {}

/**
 * Folds a column of device rows into logical segments (one per
 * share_index — one guardian) (2026-09-19 DK: the same share_index
 * appears once per guardian's device. Audit designation / revocation
 * events are per guardian).
 */
function logicalShares<T extends { readonly shareIndex: number; readonly guardianUserId: string }>(
  rows: readonly T[],
): readonly T[] {
  const seen = new Set<number>();
  return rows.filter((row) => {
    if (seen.has(row.shareIndex)) {
      return false;
    }
    seen.add(row.shareIndex);
    return true;
  });
}

function toMode(value: string): GuardianMode {
  return value === "all" ? "all" : "any";
}

function toShare(row: {
  readonly shareIndex: number;
  readonly guardianUserId: string;
  readonly guardianEncPubHex: string;
  readonly guardianKeyFingerprintHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
}): GuardianShareRecord {
  return {
    shareIndex: row.shareIndex,
    guardianUserId: row.guardianUserId,
    guardianEncPubHex: row.guardianEncPubHex,
    guardianKeyFingerprintHex: row.guardianKeyFingerprintHex,
    encHex: row.encHex,
    ciphertextHex: row.ciphertextHex,
  };
}

export function makeKeyWrapRepo(db: Db): KeyWrapRepoShape {
  // Conditional INSERT…SELECT for audit rows (guardianCreate: only when
  // "a group row was inserted"; guardianDelete: only when "a group row
  // was deleted" = bundled 1:1 via the changes() chain)
  const guardedAuditInsert = (
    event: D1AuditEventInput,
    nowMs: number,
    source: SQLiteTable | SQL,
    condition: SQL | undefined,
  ) =>
    db.insert(userAuditEvents).select(
      db
        .select(
          guardedAuditSelectColumns({
            event: event.event,
            actor: event.actor,
            nowMs,
            targetUserId: event.targetUserId ?? null,
            ...(event.payload === undefined ? {} : { payload: event.payload }),
          }),
        )
        .from(source)
        .where(condition),
    );

  const loginQuery = (userId: string) =>
    db
      .select({ login: linkedIdentities.providerLogin })
      .from(linkedIdentities)
      .where(and(eq(linkedIdentities.userId, userId), eq(linkedIdentities.provider, "github")))
      .get();

  const groupsWithShares = async (
    rows: readonly {
      readonly id: string;
      readonly userId: string;
      readonly mode: string;
      readonly suite: string;
      readonly nonceHex: string;
      readonly ciphertextHex: string;
      readonly createdAt: number;
    }[],
  ): Promise<GuardianGroupRecord[]> => {
    if (rows.length === 0) {
      return [];
    }
    const shares = await db
      .select()
      .from(guardianShares)
      .where(
        inArray(
          guardianShares.groupId,
          rows.map((r) => r.id),
        ),
      );
    return rows.map((row) => ({
      groupId: row.id,
      userId: row.userId,
      mode: toMode(row.mode),
      wrap: { suite: row.suite, nonceHex: row.nonceHex, ciphertextHex: row.ciphertextHex },
      createdAtMs: row.createdAt,
      shares: shares
        .filter((s) => s.groupId === row.id)
        .toSorted((a, b) => a.shareIndex - b.shareIndex)
        .map(toShare),
    }));
  };

  const findGroup = async (
    userId: string,
    groupId: string,
  ): Promise<GuardianGroupRecord | null> => {
    const rows = await db
      .select()
      .from(guardianGroups)
      .where(and(eq(guardianGroups.userId, userId), eq(guardianGroups.id, groupId)));
    const [group] = await groupsWithShares(rows);
    return group ?? null;
  };

  return {
    consumeWindow: ({ userId, kind, limit, nowMs, audit }) =>
      run(async () => {
        // The window-expiry check uses the difference between the
        // INSERT…ON CONFLICT excluded row (= this call's nowMs) and the
        // existing row: expired → reset; within the window → increment
        // only when count < limit. If WHERE is false nothing is updated
        // and RETURNING yields 0 rows = refusal
        const expired = sql`excluded.window_start - ${keyWrapWindows.windowStart} >= ${KEY_WRAP_WINDOW_MS}`;
        const upsert = db
          .insert(keyWrapWindows)
          .values({ userId, kind, windowStart: nowMs, count: 1 })
          .onConflictDoUpdate({
            target: [keyWrapWindows.userId, keyWrapWindows.kind],
            set: {
              windowStart: sql`case when ${expired} then excluded.window_start else ${keyWrapWindows.windowStart} end`,
              count: sql`case when ${expired} then 1 else ${keyWrapWindows.count} + 1 end`,
            },
            setWhere: sql`(${expired}) or ${keyWrapWindows.count} < ${limit}`,
          })
          .returning({ count: keyWrapWindows.count });
        const results =
          audit === undefined
            ? await db.batch([upsert])
            : await db.batch([
                upsert,
                db.insert(userAuditEvents).select(
                  db
                    .select(
                      guardedAuditSelectColumns({
                        event: audit.event,
                        actor: audit.actor,
                        nowMs,
                        targetUserId: audit.targetUserId ?? null,
                        ...(audit.payload === undefined ? {} : { payload: audit.payload }),
                      }),
                    )
                    .from(keyWrapWindows)
                    .where(
                      and(
                        eq(keyWrapWindows.userId, userId),
                        eq(keyWrapWindows.kind, kind),
                        sql`changes() = 1`,
                      ),
                    ),
                ),
              ]);
        if (results[0].length === 1) {
          return { allowed: true } as const;
        }
        const row = await db
          .select({ windowStart: keyWrapWindows.windowStart })
          .from(keyWrapWindows)
          .where(and(eq(keyWrapWindows.userId, userId), eq(keyWrapWindows.kind, kind)))
          .get();
        const remainingMs =
          row === undefined ? KEY_WRAP_WINDOW_MS : KEY_WRAP_WINDOW_MS - (nowMs - row.windowStart);
        return {
          allowed: false,
          retryAfterSeconds: Math.max(1, Math.ceil(remainingMs / 1000)),
        } as const;
      }),
    resetWindow: (userId, kind) =>
      run(async () => {
        await db
          .delete(keyWrapWindows)
          .where(and(eq(keyWrapWindows.userId, userId), eq(keyWrapWindows.kind, kind)));
      }),

    passkeyInsert: ({ userId, wrapId, params, wrap, limit, nowMs, actor }) =>
      run(async () => {
        // Cap check and insert in the same INSERT…SELECT…WHERE
        // (concurrent registrations cannot overrun — same shape as the
        // invitations pending cap)
        // The cap and the id collision (client-assigned — the AAD binds
        // wrap_id) are tested in the same WHERE; on 0 rows, the id's
        // existence distinguishes conflict / limit
        const underLimit = sql<boolean>`(select count(*) from ${masterKeyWraps} where ${masterKeyWraps.userId} = ${userId}) < ${limit} and not exists (select 1 from ${masterKeyWraps} where ${masterKeyWraps.id} = ${wrapId})`;
        const results = await db.batch([
          db
            .insert(masterKeyWraps)
            .select(
              db
                .select({
                  id: sql<string>`${wrapId}`.as("id"),
                  userId: sql<string>`${userId}`.as("user_id"),
                  kind: sql<string>`'passkey-prf'`.as("kind"),
                  suite: sql<string>`${wrap.suite}`.as("suite"),
                  params: sql<string>`${params}`.as("params"),
                  nonceHex: sql<string>`${wrap.nonceHex}`.as("nonce_hex"),
                  ciphertextHex: sql<string>`${wrap.ciphertextHex}`.as("ciphertext_hex"),
                  createdAt: sql<number>`${nowMs}`.as("created_at"),
                  updatedAt: sql<number>`${nowMs}`.as("updated_at"),
                })
                .from(sql`(select 1)`)
                .where(underLimit),
            )
            .returning({ id: masterKeyWraps.id }),
          db.insert(userAuditEvents).select(
            db
              .select(
                guardedAuditSelectColumns({
                  event: "auth.key_wrap_registered",
                  actor,
                  nowMs,
                  payload: { kind: "passkey-prf", wrapId },
                }),
              )
              .from(masterKeyWraps)
              .where(and(eq(masterKeyWraps.id, wrapId), sql`changes() = 1`)),
          ),
        ]);
        if (results[0].length === 1) {
          return "created";
        }
        const taken = await db
          .select({ id: masterKeyWraps.id })
          .from(masterKeyWraps)
          .where(eq(masterKeyWraps.id, wrapId))
          .get();
        return taken === undefined ? "limit" : "conflict";
      }),
    passkeyFind: (userId, wrapId) =>
      run(async () => {
        const row = await db
          .select()
          .from(masterKeyWraps)
          .where(and(eq(masterKeyWraps.userId, userId), eq(masterKeyWraps.id, wrapId)))
          .get();
        return row === undefined ? null : toPasskeyRecord(row);
      }),
    passkeyList: (userId) =>
      run(async () => {
        const rows = await db
          .select()
          .from(masterKeyWraps)
          .where(eq(masterKeyWraps.userId, userId))
          .orderBy(masterKeyWraps.createdAt);
        return rows.map(toPasskeyRecord);
      }),
    passkeyDelete: (userId, wrapId, nowMs, actor) =>
      run(async () => {
        const results = await db.batch([
          db
            .delete(masterKeyWraps)
            .where(and(eq(masterKeyWraps.userId, userId), eq(masterKeyWraps.id, wrapId)))
            .returning({ id: masterKeyWraps.id }),
          db.insert(userAuditEvents).select(
            db
              .select(
                guardedAuditSelectColumns({
                  event: "auth.key_wrap_removed",
                  actor,
                  nowMs,
                  payload: { kind: "passkey-prf", wrapId },
                }),
              )
              .from(sql`(select 1)`)
              .where(sql`changes() = 1`),
          ),
        ]);
        return results[0].length === 1;
      }),

    missingUsers: (userIds) =>
      run(async () => {
        if (userIds.length === 0) {
          return [];
        }
        const rows = await db
          .select({ id: users.id })
          .from(users)
          .where(inArray(users.id, [...userIds]));
        const present = new Set(rows.map((r) => r.id));
        return userIds.filter((id) => !present.has(id));
      }),
    guardianCreate: ({ userId, groupId, mode, wrap, shares, limit, nowMs, actor }) =>
      run(async () => {
        const underLimit = sql<boolean>`(select count(*) from ${guardianGroups} where ${guardianGroups.userId} = ${userId}) < ${limit} and not exists (select 1 from ${guardianGroups} where ${guardianGroups.id} = ${groupId})`;
        // The group row goes through a capped INSERT…SELECT; the segment
        // rows and the audit enter only when "a group row was inserted
        // (changes() = 1)" in the same batch. D1 batches are atomic
        const groupInsert = db
          .insert(guardianGroups)
          .select(
            db
              .select({
                id: sql<string>`${groupId}`.as("id"),
                userId: sql<string>`${userId}`.as("user_id"),
                mode: sql<string>`${mode}`.as("mode"),
                suite: sql<string>`${wrap.suite}`.as("suite"),
                nonceHex: sql<string>`${wrap.nonceHex}`.as("nonce_hex"),
                ciphertextHex: sql<string>`${wrap.ciphertextHex}`.as("ciphertext_hex"),
                createdAt: sql<number>`${nowMs}`.as("created_at"),
              })
              .from(sql`(select 1)`)
              .where(underLimit),
          )
          .returning({ id: guardianGroups.id });
        // Segments are inserted only when "the preceding statement
        // inserted 1 row" (the changes() chain: if the group row does not
        // go in, the first segment yields 0 rows and the rest stay at 0).
        // Conditioning on the id's existence would, on a client-assigned
        // id collision, try to append segments to the existing group and
        // end in a PK violation = defect
        const created = sql`changes() = 1`;
        const shareInserts = shares.map((share) =>
          db.insert(guardianShares).select(
            db
              .select({
                groupId: sql<string>`${groupId}`.as("group_id"),
                shareIndex: sql<number>`${share.shareIndex}`.as("share_index"),
                guardianUserId: sql<string>`${share.guardianUserId}`.as("guardian_user_id"),
                guardianEncPubHex: sql<string>`${share.guardianEncPubHex}`.as(
                  "guardian_enc_pub_hex",
                ),
                guardianKeyFingerprintHex: sql<string>`${share.guardianKeyFingerprintHex}`.as(
                  "guardian_key_fingerprint_hex",
                ),
                encHex: sql<string>`${share.encHex}`.as("enc_hex"),
                ciphertextHex: sql<string>`${share.ciphertextHex}`.as("ciphertext_hex"),
              })
              .from(sql`(select 1)`)
              .where(created),
          ),
        );
        // The audit row is also bundled in the same batch (same shape as
        // passkeyInsert): it enters via INSERT…SELECT only when the group
        // row went in (the changes() chain still at 1). 0 rows on cap /
        // collision → 0 audit rows. Splitting into a second batch would
        // open a "row exists but no audit" window, and a retry after
        // failure would create a second group under a different id
        const audited = and(
          eq(guardianGroups.id, groupId),
          eq(guardianGroups.userId, userId),
          created,
        );
        const auditEvents: D1AuditEventInput[] = [
          {
            event: "auth.key_wrap_registered",
            actor,
            payload: { kind: "guardian", groupId, mode, recipientCount: shares.length },
          },
          // Designation is one event per logical segment (guardian) —
          // not per device row (2026-09-19 DK)
          ...logicalShares(shares).map((share): D1AuditEventInput => ({
            event: "auth.guardian_designated",
            actor,
            targetUserId: share.guardianUserId,
            payload: { groupId, mode, shareIndex: share.shareIndex },
          })),
        ];
        const auditInserts = auditEvents.map((event) =>
          guardedAuditInsert(event, nowMs, guardianGroups, audited),
        );
        const results = await db.batch([groupInsert, ...shareInserts, ...auditInserts]);
        if (results[0].length !== 1) {
          const taken = await db
            .select({ id: guardianGroups.id })
            .from(guardianGroups)
            .where(eq(guardianGroups.id, groupId))
            .get();
          return taken === undefined ? "limit" : "conflict";
        }
        return "created";
      }),
    guardianFind: (userId, groupId) => run(() => findGroup(userId, groupId)),
    guardianList: (userId) =>
      run(async () => {
        const rows = await db
          .select()
          .from(guardianGroups)
          .where(eq(guardianGroups.userId, userId))
          .orderBy(guardianGroups.createdAt);
        return groupsWithShares(rows);
      }),
    guardianDelete: (userId, groupId, nowMs, actor) =>
      run(async () => {
        const group = await findGroup(userId, groupId);
        if (group === null) {
          return false;
        }
        // Since another party may delete between findGroup and the
        // batch, audit rows enter via INSERT…SELECT only when "a group
        // row was deleted (changes() = 1)" (same shape as passkeyDelete).
        // The losing delete yields 0 rows and its audit 0 rows = a 1:1
        // event record.
        const deleted = sql`changes() = 1`;
        const auditEvents: D1AuditEventInput[] = [
          {
            event: "auth.key_wrap_removed",
            actor,
            payload: { kind: "guardian", groupId },
          },
          ...logicalShares(group.shares).map((share): D1AuditEventInput => ({
            event: "auth.guardian_released",
            actor,
            targetUserId: share.guardianUserId,
            payload: { groupId, mode: group.mode, shareIndex: share.shareIndex },
          })),
        ];
        const results = await db.batch([
          db.delete(guardianShares).where(eq(guardianShares.groupId, groupId)),
          db
            .delete(guardianGroups)
            .where(eq(guardianGroups.id, groupId))
            .returning({ id: guardianGroups.id }),
          ...auditEvents.map((event) => guardedAuditInsert(event, nowMs, sql`(select 1)`, deleted)),
        ]);
        return results[1].length === 1;
      }),
    sharesOfGuardian: (guardianUserId, wardUserId) =>
      run(async () => {
        const rows = await db
          .select({
            wardUserId: guardianGroups.userId,
            groupId: guardianShares.groupId,
            mode: guardianGroups.mode,
            shareIndex: guardianShares.shareIndex,
            guardianKeyFingerprintHex: guardianShares.guardianKeyFingerprintHex,
            guardianEncPubHex: guardianShares.guardianEncPubHex,
            encHex: guardianShares.encHex,
            ciphertextHex: guardianShares.ciphertextHex,
            createdAt: guardianGroups.createdAt,
          })
          .from(guardianShares)
          .innerJoin(guardianGroups, eq(guardianShares.groupId, guardianGroups.id))
          .where(
            wardUserId === undefined
              ? eq(guardianShares.guardianUserId, guardianUserId)
              : and(
                  eq(guardianShares.guardianUserId, guardianUserId),
                  eq(guardianGroups.userId, wardUserId),
                ),
          )
          // Device rows in FP order (makes the head row of distribution deterministic — design record §8 K3-10)
          .orderBy(guardianGroups.createdAt, guardianShares.guardianKeyFingerprintHex);
        const wardIds = [...new Set(rows.map((r) => r.wardUserId))];
        const logins =
          wardIds.length === 0
            ? []
            : await db
                .select({ userId: linkedIdentities.userId, login: linkedIdentities.providerLogin })
                .from(linkedIdentities)
                .where(
                  and(
                    inArray(linkedIdentities.userId, wardIds),
                    eq(linkedIdentities.provider, "github"),
                  ),
                );
        const loginOf = new Map(logins.map((l) => [l.userId, l.login]));
        return rows.map((row) => ({
          wardUserId: row.wardUserId,
          wardLogin: loginOf.get(row.wardUserId) ?? null,
          groupId: row.groupId,
          mode: toMode(row.mode),
          shareIndex: row.shareIndex,
          guardianKeyFingerprintHex: row.guardianKeyFingerprintHex,
          guardianEncPubHex: row.guardianEncPubHex,
          encHex: row.encHex,
          ciphertextHex: row.ciphertextHex,
          createdAtMs: row.createdAt,
        }));
      }),

    handoffCreate: ({ requestId, userId, ttlMs, nowMs, actor }) =>
      run(async () => {
        const results = await db.batch([
          db
            .insert(keyHandoffRequests)
            .values({
              id: requestId,
              userId,
              createdAt: nowMs,
              expiresAt: nowMs + ttlMs,
              collectedAt: null,
            })
            .onConflictDoNothing()
            .returning({ id: keyHandoffRequests.id }),
          db.insert(userAuditEvents).select(
            db
              .select(
                guardedAuditSelectColumns({
                  event: "auth.key_handoff_requested",
                  actor,
                  nowMs,
                  payload: { requestId },
                }),
              )
              .from(sql`(select 1)`)
              .where(sql`changes() = 1`),
          ),
        ]);
        return results[0].length === 1 ? "created" : "conflict";
      }),
    handoffFind: (requestId, nowMs) =>
      run(async () => {
        const row = await db
          .select()
          .from(keyHandoffRequests)
          .where(eq(keyHandoffRequests.id, requestId))
          .get();
        if (row === undefined || row.expiresAt <= nowMs) {
          return null;
        }
        return {
          requestId: row.id,
          userId: row.userId,
          createdAtMs: row.createdAt,
          expiresAtMs: row.expiresAt,
          collectedAtMs: row.collectedAt,
        };
      }),
    handoffApprove: ({ requestId, wardUserId, approverUserId, approval, limit, nowMs, actor }) =>
      run(async () => {
        // The cap is a declaration of the acceptance policy (§13-8). The
        // effective bound is carried structurally by the PK `(request_id,
        // source, share_index)` plus the handler's role check (limit = 1
        // + group count × segment cap = the maximum reachable row count),
        // so even with a race window in this read-then-write the row
        // count cannot exceed limit
        const existing = await db
          .select({ n: count() })
          .from(keyHandoffApprovals)
          .where(eq(keyHandoffApprovals.requestId, requestId))
          .get();
        if ((existing?.n ?? 0) >= limit) {
          return "exceeded";
        }
        const results = await db.batch([
          db
            .insert(keyHandoffApprovals)
            .values(approvalRow(requestId, approverUserId, approval, nowMs))
            .onConflictDoNothing()
            .returning({ requestId: keyHandoffApprovals.requestId }),
          db.insert(userAuditEvents).select(
            db
              .select(
                guardedAuditSelectColumns({
                  event: "auth.key_handoff_approved",
                  actor,
                  nowMs,
                  targetUserId: wardUserId,
                  payload: {
                    requestId,
                    source: approval.source,
                    shareIndex: approval.shareIndex,
                    approverKeyFingerprintHex: approval.approverKeyFingerprintHex,
                  },
                }),
              )
              .from(sql`(select 1)`)
              .where(sql`changes() = 1`),
          ),
        ]);
        return results[0].length === 1 ? "created" : "conflict";
      }),
    handoffApprovals: (requestId) =>
      run(async () => {
        const rows = await db
          .select()
          .from(keyHandoffApprovals)
          .where(eq(keyHandoffApprovals.requestId, requestId))
          .orderBy(keyHandoffApprovals.createdAt);
        return rows.map((row) => ({
          source: row.source,
          shareIndex: row.shareIndex,
          approverUserId: row.approverUserId,
          approverKeyFingerprintHex: row.approverKeyFingerprintHex,
          encHex: row.encHex,
          ciphertextHex: row.ciphertextHex,
          createdAtMs: row.createdAt,
        }));
      }),
    handoffMarkCollected: (requestId, approvalCount, nowMs, actor) =>
      run(async () => {
        // Sets collected_at only while it is NULL, and records audit
        // exactly that once (does not keep writing "a restore happened"
        // on every poll)
        await db.batch([
          db
            .update(keyHandoffRequests)
            .set({ collectedAt: nowMs })
            .where(
              and(eq(keyHandoffRequests.id, requestId), isNull(keyHandoffRequests.collectedAt)),
            ),
          db.insert(userAuditEvents).select(
            db
              .select(
                guardedAuditSelectColumns({
                  event: "auth.key_handoff_collected",
                  actor,
                  nowMs,
                  payload: { requestId, approvalCount },
                }),
              )
              .from(sql`(select 1)`)
              .where(sql`changes() = 1`),
          ),
        ]);
      }),
    handoffDelete: (requestId, userId) =>
      run(async () => {
        const rows = await db
          .delete(keyHandoffRequests)
          .where(and(eq(keyHandoffRequests.id, requestId), eq(keyHandoffRequests.userId, userId)))
          .returning({ id: keyHandoffRequests.id });
        return rows.length === 1;
      }),
    handoffSweep: (nowMs) =>
      run(async () => {
        await db
          .delete(keyHandoffRequests)
          .where(lte(keyHandoffRequests.expiresAt, nowMs - HANDOFF_SWEEP_GRACE_MS));
      }),
    loginOf: (userId) =>
      run(async () => {
        const row = await loginQuery(userId);
        return row?.login ?? null;
      }),
  };
}

/** The approval insert row (guardian segments only — the old device-path blob column was removed under DK K4). */
function approvalRow(
  requestId: string,
  approverUserId: string,
  approval: HandoffApprovalInput,
  nowMs: number,
) {
  return {
    requestId,
    source: approval.source,
    shareIndex: approval.shareIndex,
    approverUserId,
    approverKeyFingerprintHex: approval.approverKeyFingerprintHex,
    encHex: approval.encHex,
    ciphertextHex: approval.ciphertextHex,
    createdAt: nowMs,
  };
}

function toPasskeyRecord(row: {
  readonly id: string;
  readonly params: string;
  readonly suite: string;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  readonly createdAt: number;
  readonly updatedAt: number;
}): PasskeyWrapRecord {
  return {
    wrapId: row.id,
    params: row.params,
    wrap: { suite: row.suite, nonceHex: row.nonceHex, ciphertextHex: row.ciphertextHex },
    createdAtMs: row.createdAt,
    updatedAtMs: row.updatedAt,
  };
}
