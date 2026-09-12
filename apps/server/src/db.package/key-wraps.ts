// master 鍵ラップ台帳のリポジトリ(AUTH_SPEC §13-6〜13-10 — KL3)。
//
// - Drizzle の型・クエリはこのファイル(db.package 境界内)に閉じる。公開シェイプは
//   ../key-wrap-domain.ts のドメイン型と Effect のみ
// - 監査(AUDIT_SPEC §3.1 の KL3 9 事件)はレコード操作と同一 batch で記録する。
//   拒否(429 / 404 / 409 / 422)は記録しない(受理していないものを記録しない —
//   §13-10)
// - §13-8 の固定窓は `key_wrap_windows`(user × kind)の**単一の条件付き UPSERT**で
//   数える(RecoveryRepo.recordFetch と同じ設計: 読み → 書きの 2 段だと並行
//   リクエストが同じ count を読んで計数が進まない)。許可 = RETURNING が 1 行、
//   監査は `changes() = 1` ガードの INSERT…SELECT で許可と 1:1 に同梱する
// - ラップ・分片はサーバーから見て不透明であり、このファイルは中身を解釈しない

import { and, count, eq, inArray, isNull, lte, sql } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
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
import {
  type D1AuditActor,
  type D1AuditEventInput,
  guardedAuditSelectColumns,
  userAuditInsert,
} from "./audit.ts";
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

/** D1 の障害は defect(Effect.promise)。ドメイン上の分岐だけを値で返す。 */
const run = <A>(thunk: () => Promise<A>): Effect.Effect<A> => Effect.promise(thunk);

/** §13-8 の固定窓の長さ(すべて 1 時間)。 */
const KEY_WRAP_WINDOW_MS = 60 * 60 * 1000;
/** ブロブ取得の合算上限(§13-8 — §13-3 の 5 回 / 時を種別合算に読み替え)。 */
export const KEY_BLOB_FETCH_LIMIT = 5;
/** ハンドオフ要求の上限(§13-8: 5 回 / 時 / ward)。 */
export const HANDOFF_REQUEST_LIMIT = 5;
/** 承認窓の上限(§13-8: 分片取得 + 承認で 20 回 / 時 / 承認者)。 */
export const APPROVAL_LIMIT = 20;

/** 失効した要求の日和見削除の猶予(失効後 1 時間を過ぎた行を消す)。 */
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
  readonly blob: MasterKeyWrapBlob | null;
}

export interface KeyWrapRepoShape {
  // --- 固定窓(§13-8)-------------------------------------------------------
  /**
   * 窓を 1 消費する。`audit` があれば、許可のときだけ同一 batch で記録する
   * (拒否は記録しない)。承認のように記録を別の挿入と同梱する経路は省略する。
   */
  readonly consumeWindow: (input: {
    readonly userId: string;
    readonly kind: KeyWrapWindowKind;
    readonly limit: number;
    readonly nowMs: number;
    readonly audit?: D1AuditEventInput;
  }) => Effect.Effect<KeyWrapWindowDecision>;
  /** 窓のリセット(recovery-code の再発行 — 旧ブロブへの試行履歴を新ブロブに引き継がない)。 */
  readonly resetWindow: (userId: string, kind: KeyWrapWindowKind) => Effect.Effect<void>;

  // --- クラス S(passkey-prf)------------------------------------------------
  readonly passkeyInsert: (input: {
    readonly userId: string;
    readonly wrapId: string;
    readonly params: string;
    readonly wrap: MasterKeyWrapBlob;
    readonly limit: number;
    readonly nowMs: number;
    readonly actor: D1AuditActor;
  }) => Effect.Effect<"created" | "limit">;
  readonly passkeyFind: (userId: string, wrapId: string) => Effect.Effect<PasskeyWrapRecord | null>;
  readonly passkeyList: (userId: string) => Effect.Effect<readonly PasskeyWrapRecord[]>;
  readonly passkeyDelete: (
    userId: string,
    wrapId: string,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<boolean>;

  // --- クラス G(保護者グループ)---------------------------------------------
  /** 実在しない user_id を返す(保護者の存在検査)。 */
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
  }) => Effect.Effect<"created" | "limit">;
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
  /** 保護者から見た自分の分片(任意で ward を絞る)。 */
  readonly sharesOfGuardian: (
    guardianUserId: string,
    wardUserId?: string,
  ) => Effect.Effect<readonly WardShareRecord[]>;

  // --- クラス H(ハンドオフ)--------------------------------------------------
  readonly handoffCreate: (input: {
    readonly requestId: string;
    readonly userId: string;
    readonly ttlMs: number;
    readonly nowMs: number;
    readonly actor: D1AuditActor;
  }) => Effect.Effect<"created" | "conflict">;
  /** 失効していない要求のみ返す。 */
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
  /** 初回の取得(1 件以上)を 1 回だけ auth.key_handoff_collected として記録する。 */
  readonly handoffMarkCollected: (
    requestId: string,
    approvalCount: number,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<void>;
  readonly handoffDelete: (requestId: string, userId: string) => Effect.Effect<boolean>;
  /** 失効 + 猶予を過ぎた要求の日和見削除(承認は cascade で消える)。 */
  readonly handoffSweep: (nowMs: number) => Effect.Effect<void>;
  /** 表示用の login スナップショット(github)。 */
  readonly loginOf: (userId: string) => Effect.Effect<string | null>;
}

export class KeyWrapRepo extends Context.Service<KeyWrapRepo, KeyWrapRepoShape>()("KeyWrapRepo") {}

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
        // 窓の期限判定は INSERT…ON CONFLICT の excluded 行(= 今回の nowMs)と既存行
        // の差で行う。期限切れならリセット、窓内なら count < limit のときだけ加算。
        // WHERE が偽なら何も更新されず RETURNING は 0 行 = 拒否
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
        // 上限判定と挿入を同一の INSERT…SELECT…WHERE で行う(並行登録で上限を
        // 超えない — invitations の pending 上限と同じ形)
        const underLimit = sql<boolean>`(select count(*) from ${masterKeyWraps} where ${masterKeyWraps.userId} = ${userId}) < ${limit}`;
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
        return results[0].length === 1 ? "created" : "limit";
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
        const underLimit = sql<boolean>`(select count(*) from ${guardianGroups} where ${guardianGroups.userId} = ${userId}) < ${limit}`;
        // グループ行は上限付き INSERT…SELECT、分片行と監査は「グループ行が入った
        // (changes() = 1)」ときだけ入る同一 batch。D1 の batch は原子的
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
        const created = sql`exists (select 1 from ${guardianGroups} where ${guardianGroups.id} = ${groupId})`;
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
        const audits = [
          userAuditInsert(db, nowMs, {
            event: "auth.key_wrap_registered",
            actor,
            payload: { kind: "guardian", groupId, mode, recipientCount: shares.length },
          }),
          ...shares.map((share) =>
            userAuditInsert(db, nowMs, {
              event: "auth.guardian_designated",
              actor,
              targetUserId: share.guardianUserId,
              payload: { groupId, mode, shareIndex: share.shareIndex },
            }),
          ),
        ];
        // 監査行は上限で拒否されたときに入ってはならない。userAuditInsert は
        // 無条件 INSERT なので、グループ挿入の結果を先に確定してから 2 段目の
        // batch で入れる(D1 は batch 間の原子性を持たないが、グループ行 → 監査の
        // 順なら「行があるのに監査がない」窓が極小の障害時にしか生じない)
        const first = await db.batch([groupInsert, ...shareInserts]);
        if (first[0].length !== 1) {
          return "limit";
        }
        await db.batch([audits[0]!, ...audits.slice(1)]);
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
        await db.batch([
          db.delete(guardianShares).where(eq(guardianShares.groupId, groupId)),
          db.delete(guardianGroups).where(eq(guardianGroups.id, groupId)),
          userAuditInsert(db, nowMs, {
            event: "auth.key_wrap_removed",
            actor,
            payload: { kind: "guardian", groupId },
          }),
          ...group.shares.map((share) =>
            userAuditInsert(db, nowMs, {
              event: "auth.guardian_released",
              actor,
              targetUserId: share.guardianUserId,
              payload: { groupId, mode: group.mode, shareIndex: share.shareIndex },
            }),
          ),
        ]);
        return true;
      }),
    sharesOfGuardian: (guardianUserId, wardUserId) =>
      run(async () => {
        const rows = await db
          .select({
            wardUserId: guardianGroups.userId,
            groupId: guardianShares.groupId,
            mode: guardianGroups.mode,
            shareIndex: guardianShares.shareIndex,
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
          .orderBy(guardianGroups.createdAt);
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
          blob:
            row.blobSuite !== null && row.blobNonceHex !== null && row.blobCiphertextHex !== null
              ? {
                  suite: row.blobSuite,
                  nonceHex: row.blobNonceHex,
                  ciphertextHex: row.blobCiphertextHex,
                }
              : null,
          createdAtMs: row.createdAt,
        }));
      }),
    handoffMarkCollected: (requestId, approvalCount, nowMs, actor) =>
      run(async () => {
        // collected_at が NULL のときだけ立て、その 1 回だけ監査を記録する
        // (ポーリングのたびに「復元が起きた」を重ねて書かない)
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

/** 承認の挿入行(blob は device のみ — 3 列まとめて NULL か非 NULL)。 */
function approvalRow(
  requestId: string,
  approverUserId: string,
  approval: HandoffApprovalInput,
  nowMs: number,
) {
  const blob = approval.blob;
  return {
    requestId,
    source: approval.source,
    shareIndex: approval.shareIndex,
    approverUserId,
    approverKeyFingerprintHex: approval.approverKeyFingerprintHex,
    encHex: approval.encHex,
    ciphertextHex: approval.ciphertextHex,
    blobSuite: blob === null ? null : blob.suite,
    blobNonceHex: blob === null ? null : blob.nonceHex,
    blobCiphertextHex: blob === null ? null : blob.ciphertextHex,
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
