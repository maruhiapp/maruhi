// D1 リポジトリの Effect サービス実装(AUTH_SPEC §2。ADR-0006)。
//
// - Drizzle の型・クエリはこのファイル(db.package 境界内)に閉じる。公開シェイプは
//   ドメイン型(../auth-domain.ts)と Effect のみ
// - D1 の障害(接続・SQL エラー)は defect として扱う(Effect.promise)。ドメイン上
//   予期される分岐(該当なし・一意制約競合)だけを値で表現する
// - Drizzle 採用の確定判断はセッション 06: classic drizzle-orm/d1 を採用。
//   effect-d1 ドライバは rc.4 時点で transaction / batch 未対応のため、原子性が
//   必要な getOrCreateUser(§1-5)が成立しない。D1 の atomic batch を使う

import type { SignupPolicy } from "@maruhi/api-schema";
import type { OrgRole, TokenScope } from "@maruhi/core";
import { parseTokenScopes } from "@maruhi/core";
import {
  and,
  count,
  eq,
  gt,
  gte,
  inArray,
  isNull,
  lt,
  lte,
  min,
  or,
  type SQL,
  sql,
} from "drizzle-orm";
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
  InviteAcceptInput,
  InviteCompletionTarget,
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
import {
  apiTokens,
  cliLoginFlows,
  deploymentSettings,
  flowSigningKeys,
  invitations,
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
// IdentityRepo(§1-5 getOrCreateUser / §9-1 パーソナル org 自動作成)
// ---------------------------------------------------------------------------

interface IdentityRepoShape {
  /**
   * 単一の冪等な入口。新規作成時は本人 owner のパーソナル org を同時に作る。
   *
   * signupPolicy ゲート(AUTH_SPEC §3 — 2026-09-01 H1)は「不在 → 作成」分岐の
   * 直前にあり、既存ユーザーの解決には一切影響しない。`signupInviteTokenHash`
   * はサインアップ招待コード(提示文字列全体)の SHA-256(未提示は null)。
   * `invite` 下の作成はコード消費 CAS と同一 D1 batch で行われる。
   */
  readonly getOrCreateUser: (
    identity: VerifiedIdentity,
    nowMs: number,
    signupInviteTokenHash: string | null,
  ) => Effect.Effect<SignupGateResult>;
  /**
   * 照会のみ(作成しない — AUTH_SPEC §4-1 (4) (ii)・裁定 DH)。CLI ログインの
   * ブラウザ脚が使う: アカウント不在はサインアップ案内で終了し、一切の
   * 不可逆な副作用を起こさない。
   */
  readonly lookupUser: (identity: VerifiedIdentity) => Effect.Effect<string | null>;
  /** ユーザーが属する org 一覧(プロジェクト作成先の発見用。§11-3)。 */
  readonly listUserOrgs: (userId: string) => Effect.Effect<readonly UserOrg[]>;
  /**
   * 受理時点の signupPolicy(AUTH_SPEC §3)。行なし = 'open'(既定 = 従来挙動)、
   * 未知の保存値 = 'closed'(fail-closed — 運営の誤設定を黙って 'open' に
   * 化けさせない)。`/auth/config` の advisory と CLI サインアップ案内ページの
   * 文言分岐が読む。
   */
  readonly signupPolicy: Effect.Effect<SignupPolicy>;
  /**
   * サインアップ招待コードの事前検証(AUTH_SPEC §3 — start の開始時 fail-fast)。
   * 存在・未消費・未失効のときのみ true。256-bit 乱数・単回なので存在オラクルに
   * ならない(§15 招待トークンと同水準)。消費はここでは行わない(消費は
   * getOrCreateUser の作成 batch 内の CAS のみ)。
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
 * 一意制約違反かどうかを D1 のエラーメッセージで判別する。競合以外の失敗
 * (一時障害・FK 違反等)を「競合」に誤分類すると再ルックアップが空になり、
 * 実態と異なる defect メッセージで障害調査を誤誘導するため区別する。
 * drizzle は経路によってエラーを `cause` にラップする(batch は素通し、単発
 * クエリは DrizzleQueryError)ため、cause 連鎖も辿る。テスト用に公開する。
 */
export function isUniqueConflict(error: unknown): boolean {
  for (let current = error; current instanceof Error; current = current.cause) {
    if (current.message.includes("UNIQUE constraint failed")) {
      return true;
    }
  }
  return false;
}

/** deployment_settings の signupPolicy キー(AUTH_SPEC §3)。 */
const SIGNUP_POLICY_KEY = "signup_policy";

// 未知の保存値の fail-closed 警告は isolate ごとに 1 回だけ出す(/auth/config は
// 外形監視が定期的に叩く面 — hosted-design.md §5-2 — であり、毎回の warn は
// ログを溢れさせる)。メッセージは静的(保存値そのものは書かない — §11-5 の規律)
let warnedUnknownSignupPolicy = false;

/**
 * 受理時点の signupPolicy の読み取り(AUTH_SPEC §3)。行なし = 'open'、
 * 未知の値 = 'closed'(fail-closed)。
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
 * 作成 batch 内で評価する signupPolicy 条件(AUTH_SPEC §3 —「判定は受理時点の
 * 設定」)。読み取り(readSignupPolicy)と作成の間に設定が遷移しても、作成が
 * 効くのはこの条件が batch のトランザクション内で真のときだけ — 遷移との競合窓を
 * 作らない(§12-11 の DO 直列化に相当する D1 形)。行なしの既定 'open' は
 * coalesce が畳む。
 */
function signupPolicyIs(value: SignupPolicy): SQL {
  return sql`(select coalesce((select ${deploymentSettings.value} from ${deploymentSettings} where ${deploymentSettings.key} = ${SIGNUP_POLICY_KEY}), 'open')) = ${value}`;
}

/** 作成ゲートの指定(AUTH_SPEC §3): open のポリシー条件か、invite の消費 CAS。 */
type SignupGate =
  | { readonly kind: "open" }
  | { readonly kind: "invite"; readonly inviteId: string };

/** ゲート敗北(ポリシー遷移・招待コードの並行消費)。呼び出し側が再判定する。 */
class SignupGateLostError extends Data.TaggedError("SignupGateLost")<object> {}

/**
 * users + linked_identities + パーソナル org + owner membership を atomic batch で
 * 作成する。並行サインアップは (provider, provider_user_id) の PK で片方が失敗する
 * ので、競合時は呼び出し側が再ルックアップする。競合以外の失敗は defect。
 *
 * signupPolicy ゲート(AUTH_SPEC §3 — 2026-09-01 H1)は batch 先頭の条件として
 * 畳む: open は先頭 INSERT の WHERE にポリシー条件、invite は先頭の消費 CAS
 * (UPDATE — pending・未失効・ポリシー 'invite' のときのみ効く)。後続の全文は
 * `changes() = 1` で直前の成立に連鎖する(tokenInsertSelect と同じ D1 batch の
 * 作法)ため、ゲートが負けた batch は**何も書かずに**コミットされる(コードだけ
 * 燃える形・部分作成の両方が構造的に存在しない)。
 *
 * 監査(AUDIT_SPEC §3.1〜§3.2)も同じ batch で追記する: auth.user_created
 * (invite 消費由来は payload に signupInviteId — AUDIT_SPEC §3.1)/
 * auth.identity_linked(provider 種別名のみ — 数値 ID・login は記録しない)/
 * org.created(パーソナル org 自動作成。org 名は providerLogin 由来のため
 * payload に写さない — §1-2)/ org.member_added(owner 自身)。
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
  // 後続の全文は直前の文の成立(changes() = 1)に連鎖する INSERT…SELECT
  // (tokenInsertSelect と同じ形)。挿入行はすべて定数選択なので、ゲートが
  // 負けた batch では 1 行も書かれない
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
                // 消費 CAS(AUTH_SPEC §3): pending・未失効・受理時点ポリシーが
                // 'invite' のときのみ効く。作成と同一トランザクション —
                // 「作成に失敗した試行がコードだけ燃やす形」も「作成が成功した
                // のにコードが未消費で残る形」も存在しない
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
      // 競合以外の D1 障害はインフラ defect としてそのまま伝播する
      throw error;
    },
  }).pipe(
    Effect.flatMap((created) =>
      created === null ? Effect.fail(new SignupGateLostError()) : Effect.succeed(created),
    ),
  );
}

/**
 * ログイン時に verified メールを最新化する(GitHub の email API の一時障害で
 * サインアップ時に取り損ねた場合の自己修復)。null では既存値を消さない。
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

/** サインアップ招待コードの pending 行の照会(消費しない — 消費は作成 batch)。 */
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
  // signupPolicy ゲート(AUTH_SPEC §3)つきの単一の冪等な入口(§1-5)。
  // attempt は SignupGateLost(読み取りと batch の間にポリシーが遷移した・
  // 招待コードが並行消費された)の再判定回数 — 再帰は毎回設定を読み直すので
  // 定常状態では 1 回で収束する。収束しない設定の往復は運用異常(defect)
  const getOrCreateUser = (
    identity: VerifiedIdentity,
    nowMs: number,
    signupInviteTokenHash: string | null,
    attempt = 0,
  ): Effect.Effect<SignupGateResult> =>
    Effect.flatMap(lookupLinkedUser(db, identity), (existing) => {
      if (existing !== null) {
        // 既存ユーザーはゲート非通過(AUTH_SPEC §3 — 新規作成だけを塞ぐ)。
        // 提示されたコードは消費されない
        return Effect.as(refreshVerifiedEmail(db, existing, identity, nowMs), {
          userId: existing,
          created: false,
        } satisfies ResolvedUser);
      }
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
  return {
    getOrCreateUser: (identity, nowMs, signupInviteTokenHash) =>
      getOrCreateUser(identity, nowMs, signupInviteTokenHash),
    lookupUser: (identity) => lookupLinkedUser(db, identity),
    listUserOrgs: (userId) => listUserOrgs(db, userId),
    signupPolicy: Effect.suspend(() => run(() => readSignupPolicy(db))),
    hasPendingSignupInvite: (tokenHashHex, nowMs) =>
      Effect.map(findPendingSignupInvite(db, tokenHashHex, nowMs), (row) => row !== null),
  };
}

/** batch 競合後の再ルックアップ。ここでも見つからないのは D1 障害(defect)。 */
function rerunLookup(db: Db, identity: VerifiedIdentity): Effect.Effect<ResolvedUser> {
  return Effect.flatMap(lookupLinkedUser(db, identity), (found) =>
    found === null
      ? Effect.die(new Error("linked identity insert failed without a conflicting row"))
      : Effect.succeed({ userId: found, created: false }),
  );
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
// SessionRepo(§5。id はハッシュ。生値はこの層に到達しない)
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
  /** スライディング更新(§5): last_used_at と expires_at を進める。 */
  readonly touch: (idHash: string, nowMs: number, expiresAtMs: number) => Effect.Effect<void>;
  /**
   * 明示失効(ログアウト / サーバー側失効)。auth.session_revoked を同一 batch で
   * 記録する(AUDIT_SPEC §3.1)。期限切れ掃除は deleteByHash / deleteExpired を
   * 使う(失効イベントではないため記録しない)。
   */
  readonly revokeByHash: (idHash: string, nowMs: number) => Effect.Effect<void>;
  readonly deleteByHash: (idHash: string) => Effect.Effect<void>;
  /** 期限切れ行の一括掃除(cron から呼ぶ。提示されない行はここでしか消えない)。 */
  readonly deleteExpired: (nowMs: number) => Effect.Effect<void>;
}

export class SessionRepo extends Context.Service<SessionRepo, SessionRepoShape>()("SessionRepo") {}

function makeSessionRepo(db: Db): SessionRepoShape {
  return {
    // auth.login_succeeded はセッション作成と 1:1(AUDIT_SPEC §3.1 —
    // auth.session_created を独立イベントにしない)なので同じ batch で記録する。
    // session id(= 保存 id と同じハッシュ。生値ではない — AUTH_SPEC §10)は
    // 失効イベントとの突合用に payload に写す
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
        // 削除の成立を returning で観測してからイベントを書く(actor もここから
        // 写す)。読み → 削除の 2 段だと並行ログアウトが両方 SELECT に成功して
        // 1 失効に 2 行記録し得る(Pullfrog 指摘)。削除と追記が 2 文になる分
        // 「削除だけ成功しイベントが欠ける」窓は理論上残るが、重複より欠落側に
        // 倒す。行がなければ no-op(存在しない失効をイベント化しない)
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
// TokenRepo(§6。token_hash 照合はサービス層でタイミング安全比較を併用)
// ---------------------------------------------------------------------------

export interface NewApiToken {
  readonly id: string;
  readonly userId: string;
  readonly name: string;
  readonly tokenHash: string;
  readonly tokenPrefix: string;
  readonly scopes: readonly TokenScope[];
  /** 発行時に固定される有効期限(AUTH_SPEC §6 の既定 TTL — W3a)。 */
  readonly expiresAtMs: number;
  readonly createdAtMs: number;
}

export interface TokenRepoShape {
  /**
   * 同一 (user, name) は既存トークンを失効させつつローテーションし、別名は
   * `limit` 未満のときだけ条件付き発行する。各経路を D1 の atomic batch で行い、
   * 並行発行でも同名重複・別名の上限超過を許さない。false = quota 拒否。
   *
   * 置換された旧トークン id は `auth.token_created` の payload に
   * `replacedTokenId` として載る(新規発行では現れない — AUDIT_SPEC §3.1)。
   */
  readonly issueForUserWithinLimit: (token: NewApiToken, limit: number) => Effect.Effect<boolean>;
  readonly findByHash: (tokenHash: string) => Effect.Effect<ApiTokenRecord | null>;
  readonly touchLastUsed: (id: string, nowMs: number) => Effect.Effect<void>;
  /**
   * 本人のトークン一覧(AUTH_SPEC §6 — W3a)。token_hash は選択列に含めない
   * (配布面 — ApiTokenSummary に構造ごと存在しない)。期限切れ行も返す
   * (棚卸しの対象 — 検証だけが 401 に落とす)。created_at 昇順・同時刻は id。
   */
  readonly listForUser: (userId: string) => Effect.Effect<readonly ApiTokenSummary[]>;
  /**
   * 明示失効。id × user 所有を強制し、auth.token_revoked を記録する(§3.1 / S8)。
   * actor は失効を実行した主体(指定失効ではセッション / 別トークンでありうる —
   * AUDIT_SPEC §2)。戻り値 = 実際に行が消えたか(false は呼び出し側が一様 404 を
   * 導出する — §6 の存在秘匿)。
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
 * 既存同名 token のローテーション。最初の audit INSERT が旧 id を読むため、
 * replacedTokenId は実際に同一 batch で消える行と一致する(deepsec R6)。
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

/** 新規名 token の上限判定 + INSERT を 1 文に畳む(deepsec S7)。 */
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
    // 発行上限の admission は repo 内の条件付き INSERT が担う(deepsec S7)。
    // サービス層の count → insert は別 D1 round-trip になり、異名の並行発行が
    // 同じ under-limit を観測して上限を超えられる。同名ローテーションは上限
    // 到達時も許可し、旧 id の監査(R6)も同一 batch で保つ。
    issueForUserWithinLimit: (token, limit) =>
      run(async () => {
        if (await rotateExistingToken(db, token)) {
          return true;
        }
        if (await createNewTokenWithinLimit(db, token, limit)) {
          return true;
        }
        // 最初の既存確認と新規 INSERT の間に同名 token が現れた競合。
        // 新規名の quota 拒否と区別するため、最後にローテーションを再試行する
        return rotateExistingToken(db, token);
      }),
    findByHash: (tokenHash) => run(() => findTokenByHash(db, tokenHash)),
    touchLastUsed: (id, nowMs) =>
      run(async () => {
        await db.update(apiTokens).set({ lastUsedAt: nowMs }).where(eq(apiTokens.id, id));
      }),
    listForUser: (userId) =>
      run(async () => {
        // token_hash を選択列に含めない(配布面 — auth-domain.ts の注記)。
        // 期限切れ行も返す: 一覧は棚卸し面であり、期限切れは失効(行の削除)と
        // 違って在庫として可視のまま残る(利用者が指定失効で掃除できる)
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
            // findTokenByHash と同じ規律: 自分の書き込み経路でしか生成されない
            // 列が壊れている = 実装バグ / DB 破損(黙って行を落とさない)
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
        // 削除の成立を returning で観測してからイベントを書く(revokeByHash と
        // 同型 — Cursor Security Agent 指摘対応)。並行 revoke は呼び出し側の
        // findByHash を両方通過し得るため、無条件 batch だと 1 失効に複数の
        // token_revoked を記録できてしまう(過大計上)。重複より欠落側に倒す
        const deleted = await db
          .delete(apiTokens)
          // deepsec S8: id だけで消すと token-id 指定の管理 API(W3a の指定失効)が
          // 別 user の token を失効し、監査 actor だけ呼び出し user と誤記録する。
          // 所有条件は repo 境界で強制し、0 行 = 呼び出し側の一様 404(§6)
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
    // 自分の書き込み経路でしか生成されない列が壊れている = 実装バグ / DB 破損
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
// RecoveryRepo(AUTH_SPEC §13。ブロブは user 単位で高々 1 つ)
// ---------------------------------------------------------------------------

/** ブロブ取得レート制限の固定窓(AUTH_SPEC §13-3: user あたり 1 時間 5 回)。 */
const RECOVERY_FETCH_WINDOW_MS = 60 * 60 * 1000;
export const RECOVERY_FETCH_LIMIT = 5;

interface RecoveryRepoShape {
  /**
   * 登録・再発行 = 置換 upsert(§13-1。旧ラップは受理と同時に消える)。
   * auth.recovery_code_reissued を同一 batch で記録する(AUDIT_SPEC §3.1 /
   * AUTH_SPEC §13-5。初回登録も同じ置換受理なので同一イベント)。
   */
  readonly upsert: (
    userId: string,
    wrap: { readonly suite: string; readonly nonceHex: string; readonly ciphertextHex: string },
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<void>;
  readonly find: (userId: string) => Effect.Effect<RecoveryWrapRecord | null>;
  /**
   * 固定窓の計数を進め、取得可否を返す(§13-3)。行が存在しないときは
   * allowed(404 は計数しない — 呼び出し側が find で判定する)。読み → 条件付き
   * 更新の 2 文であり、並行リクエストで計数が僅かに超過しうるベストエフォート。
   * allowed のとき auth.recovery_blob_fetched(要監視イベント — AUDIT_SPEC §3.1)
   * を計数更新と同一 batch で記録する(拒否 = 配布なしは記録しない)。
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

function makeRecoveryRepo(db: Db): RecoveryRepoShape {
  return {
    upsert: (userId, wrap, nowMs, actor) =>
      run(async () => {
        await db.batch([
          db
            .insert(recoveryWraps)
            .values({
              userId,
              suite: wrap.suite,
              nonceHex: wrap.nonceHex,
              ciphertextHex: wrap.ciphertextHex,
              createdAt: nowMs,
              updatedAt: nowMs,
              fetchWindowStart: null,
              fetchCount: 0,
            })
            .onConflictDoUpdate({
              target: recoveryWraps.userId,
              set: {
                suite: wrap.suite,
                nonceHex: wrap.nonceHex,
                ciphertextHex: wrap.ciphertextHex,
                updatedAt: nowMs,
                // 再発行は新しいブロブなので取得窓もリセットする(旧ブロブへの
                // 試行履歴を新ブロブに引き継がない)
                fetchWindowStart: null,
                fetchCount: 0,
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
    recordFetch: (userId, nowMs, actor) =>
      run(async () => {
        // 取得計数は**単一の条件付き相対 UPDATE**で行う(deepsec B9): 従来の
        // 読み → 書き 2 段は並行リクエストが同じ count を読み、複数成功しても
        // 計数が 1 しか進まなかった。窓のリセット / 加算 / 上限判定を 1 文の
        // CASE / WHERE に畳み、更新できた(= RETURNING が 1 行)ことを許可の
        // 定義にする。auth.recovery_blob_fetched は invites の CAS と同じ
        // changes() = 1 ガードの INSERT…SELECT を同一 batch に同梱し、許可された
        // 取得と 1:1 のまま原子的に記録する(AUDIT_SPEC §5.2)
        const windowExpired = sql`${recoveryWraps.fetchWindowStart} is null or ${nowMs} - ${recoveryWraps.fetchWindowStart} >= ${RECOVERY_FETCH_WINDOW_MS}`;
        const results = await db.batch([
          db
            .update(recoveryWraps)
            .set({
              fetchWindowStart: sql`case when ${windowExpired} then ${nowMs} else ${recoveryWraps.fetchWindowStart} end`,
              fetchCount: sql`case when ${windowExpired} then 1 else ${recoveryWraps.fetchCount} + 1 end`,
            })
            .where(
              and(
                eq(recoveryWraps.userId, userId),
                or(sql`(${windowExpired})`, lt(recoveryWraps.fetchCount, RECOVERY_FETCH_LIMIT)),
              ),
            )
            .returning({ fetchCount: recoveryWraps.fetchCount }),
          db.insert(userAuditEvents).select(
            db
              .select(
                guardedAuditSelectColumns({
                  event: "auth.recovery_blob_fetched",
                  actor,
                  nowMs,
                }),
              )
              .from(recoveryWraps)
              .where(and(eq(recoveryWraps.userId, userId), sql`changes() = 1`)),
          ),
        ]);
        if (results[0].length === 1) {
          return { allowed: true } as const;
        }
        // 0 行 = 対象行が無い(未登録 — 上位が 404 を導出する)か、窓内で上限到達
        const row = await db
          .select({
            fetchWindowStart: recoveryWraps.fetchWindowStart,
            fetchCount: recoveryWraps.fetchCount,
          })
          .from(recoveryWraps)
          .where(eq(recoveryWraps.userId, userId))
          .get();
        if (row === undefined) {
          return { allowed: true } as const;
        }
        const windowStart = row.fetchWindowStart;
        if (
          windowStart !== null &&
          nowMs - windowStart < RECOVERY_FETCH_WINDOW_MS &&
          row.fetchCount >= RECOVERY_FETCH_LIMIT
        ) {
          const remainingMs = RECOVERY_FETCH_WINDOW_MS - (nowMs - windowStart);
          return {
            allowed: false,
            retryAfterSeconds: Math.max(1, Math.ceil(remainingMs / 1000)),
          } as const;
        }
        // UPDATE と再読の間に別リクエストが窓をリセットした等の極小レース。
        // 安全側(拒否)に倒し、残り時間は窓の全長で案内する
        return {
          allowed: false,
          retryAfterSeconds: Math.ceil(RECOVERY_FETCH_WINDOW_MS / 1000),
        } as const;
      }),
  };
}

// ---------------------------------------------------------------------------
// OrgRepo(§9-1 org ロール。プロジェクトアクセスには関与しない)
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
// ProjectRepo(§11-3。org 帰属メタデータ + §11-5 の membership 投影。
// どちらも権限テーブルではない — 投影は発見専用の候補索引で、認可判定には
// 使わない。真実源はメンバーシップチェーン — CRYPTO_SPEC §6.4)
// ---------------------------------------------------------------------------

interface ProjectRepoShape {
  /**
   * 冪等挿入(修復経路を含む §11-3)。既存行はそのまま。org.project_created
   * (AUDIT_SPEC §3.2)と genesis actor(owner)の membership 投影行(§11-5)を
   * 同一 batch で記録する。batch の原子性により、既存行との競合で挿入が成立
   * しなかった場合は監査行も巻き戻る(空振り挿入でイベントだけ重複しない)。
   * 投影行の挿入は onConflictDoNothing: 修復経路(§11-3)では lazy upsert
   * (§11-5 の (4))が先に行を立てていることがあり、その競合で projects 行の
   * 挿入まで巻き戻してはならない。
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
   * 投影の維持(§11-5): add_member 受理後の行挿入と、チェーン取得成功時の
   * lazy 挿入(missing の自己修復 + 投影導入前プロジェクトの無人バックフィル)。
   * 冪等(INSERT OR IGNORE 相当)。
   */
  readonly upsertMember: (projectId: string, userId: string, nowMs: number) => Effect.Effect<void>;
  /**
   * 投影の維持(§11-5): remove_member 受理後と、一覧の読取時確認で DO が
   * 非メンバーと答えた stale 行の削除(チェーン truth への収束)。冪等。
   */
  readonly deleteMember: (projectId: string, userId: string) => Effect.Effect<void>;
  /**
   * 一覧の候補列挙(§11-5): 本人の投影行の project_id を昇順で、排他カーソル
   * `afterProjectId`(null = 先頭から)から最大 `limit` 件。候補にすぎない —
   * 応答へ載せてよいかは呼び出し側の DO 確認が決める。
   *
   * `withinProjectIds` はトークンスコープとの交差を**候補索引の段で**行う
   * フィルタ(null = 制限なし)。`nextAfter` は候補ページの末尾から出るため、
   * 交差を後段(応答行の絞り込み)だけに置くとスコープ外の project_id が
   * カーソルに載って漏れる(PR #106 Cursor Security Agent 指摘)— 候補空間
   * 自体をスコープ内に閉じる。
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
 * スコープ交差 IN のチャンク幅(§11-5 の候補列挙)。D1 の 1 クエリ束縛
 * パラメータ上限(100 — Cloudflare D1 limits)から userId / after / limit の
 * 3 パラメータを引いた予算内に余裕を持って収める。トークンスコープの発行時
 * 上限(100 エントリ — AUTH_SPEC §6 / api-schema)を単一 IN に流すと上限を
 * 超えるため、いずれかの上限を変更する場合は本値との整合を再確認すること。
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
          // PK 競合 = 既に作成済み。batch ごと巻き戻るため挿入・監査とも no-op
          // (冪等)。監査行だけが残る実行順は存在しない。競合以外は defect
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
        // スコープ交差の IN はチャンクして発行する(PR #106 pullfrog 指摘):
        // D1 の 1 クエリ束縛パラメータ上限は 100 で、トークンスコープの
        // スキーマ上限も 100 エントリ(api-schema auth-api.ts)— 単一 IN だと
        // userId / after / limit の 3 パラメータと合わせて上限を超え、正当に
        // 発行されたワイドスコープトークンの一覧が hard fail する。各チャンクは
        // limit 件までの昇順列を返すので、連結 + 全体ソート + limit 切りが
        // 単一クエリと同じページを与える(チャンクは互いに素な ID 集合)。
        // ループ形は保存済みスコープが発行時上限を超える旧行にも安全
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
// InviteRepo(AUTH_SPEC §15。招待レコードと invite.* 監査の同一 batch 追記)
// ---------------------------------------------------------------------------

/** §15-1 起草値: 招待の有効期間(発行 + 7 日)。 */
export const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * §15-2 起草値: 発行のレート窓(1 時間 30 回 / プロジェクト)。実装形は
 * 「直近 1 時間の invitations 行数」の lookback 計数(auth.login_failed —
 * audit.ts — と同じ、追加の窓状態を持たない形)。任意の 1 時間区間で 30 を
 * 超えない = 仕様の固定窓より緩む方向には決してならない(バケット境界の
 * リセットが無い分だけ厳しい側)。retryAfterSeconds は最古の窓内発行が
 * 窓から抜ける時刻から導出する。
 */
const INVITE_ISSUE_WINDOW_MS = 60 * 60 * 1000;
export const INVITE_ISSUE_WINDOW_LIMIT = 30;

/** §15-2 起草値: pending 招待の上限(プロジェクトあたり 100。期限切れは数えない)。 */
export const MAX_PENDING_INVITES_PER_PROJECT = 100;

interface InviteCreateInput {
  readonly id: string;
  readonly projectId: string;
  readonly tokenHashHex: string;
  readonly role: InviteRole;
  readonly inviterUserId: string;
}

interface InviteRepoShape {
  /**
   * 発行(§15-2)。受理ポリシーの判定順は仕様の記載順に固定: pending 上限 →
   * レート窓(lookback 計数 — INVITE_ISSUE_WINDOW_MS の注記参照)。両カウントを
   * `INSERT … SELECT … WHERE` の同一文で再評価し、並行発行でも上限を超えない
   * (deepsec S4)。受理時は invite.created(AUDIT_SPEC §3.2)を changes() ガード付き
   * INSERT…SELECT と同一 batch に入れ、作成と 1:1 で記録する。
   */
  readonly create: (
    input: InviteCreateInput,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<InviteIssueDecision>;
  /** トークンハッシュによる解決(受諾経路 — トークン保持が capability)。 */
  readonly findByTokenHash: (tokenHashHex: string) => Effect.Effect<InvitationRecord | null>;
  /** プロジェクト配下の id 解決(失効経路)。 */
  readonly findById: (projectId: string, id: string) => Effect.Effect<InvitationRecord | null>;
  /** 一覧(§15-2)。受諾ブロック込み — 招待者クライアントの §6.5 独立検証の材料。 */
  readonly listForProject: (projectId: string) => Effect.Effect<readonly InvitationRecord[]>;
  /**
   * 受諾の単回使用 CAS(pending → accepted — §15-1)。条件付き UPDATE と、
   * `changes() = 1` でガードした invite.accepted の INSERT…SELECT を同一 batch
   * で発行する(AUDIT_SPEC §5.2 の同一トランザクション原則)。D1 は batch を
   * 逐次・非並行・単一トランザクションと文書化しており、その逐次性から
   * changes() は直前の UPDATE の結果を参照する(RETURNING 文の消化順序までは
   * 明文化されていないため、この性質は invites.test.ts の CAS 敗北テストで
   * 実挙動としても固定する)— CAS 敗北時は監査行も 0 行のまま。戻り値は勝敗
   * のみ(敗北理由の導出は呼び出し側が再読みで行う)。
   */
  readonly acceptCas: (
    input: InviteAcceptInput,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<boolean>;
  /**
   * 失効の CAS(pending | accepted → revoked)。期限切れ pending の失効も許す
   * (管理操作の掃除)。受理時は invite.revoked を同一 batch で記録する
   * (acceptCas と同じ changes() ガード)。completed / revoked へは効かない
   * (呼び出し側が再読みで 410 を導出する)。
   */
  readonly revokeCas: (
    projectId: string,
    id: string,
    payload: { readonly role: InviteRole },
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<boolean>;
  /**
   * add_member 受理時の accepted → completed 突合(§15-2。導出状態の更新であり
   * 真実源はチェーン。§15-4: 証跡は chain.member_added — 独立イベントを書かない)。
   * 鍵一致条件(enc / sig 両方)は「この受諾がこの add_member によって成就した」
   * ことの精密化 — 別鍵の accepted 招待は据え置かれ、一覧で可視のまま残る。
   */
  readonly completeAccepted: (target: InviteCompletionTarget) => Effect.Effect<void>;
}

export class InviteRepo extends Context.Service<InviteRepo, InviteRepoShape>()("InviteRepo") {}

/** 行 → ドメイン表現(受諾ブロックは 5 列すべて揃っているときのみ)。 */
function toInvitationRecord(row: {
  readonly id: string;
  readonly projectId: string;
  readonly tokenHash: string;
  readonly role: string;
  readonly inviterUserId: string;
  readonly status: string;
  readonly expiresAt: number;
  readonly inviteeUserId: string | null;
  readonly inviteeEncPub: string | null;
  readonly inviteeSigPub: string | null;
  readonly acceptSignature: string | null;
  readonly acceptedAt: number | null;
  readonly createdAt: number;
}): InvitationRecord {
  const acceptance =
    row.inviteeUserId !== null &&
    row.inviteeEncPub !== null &&
    row.inviteeSigPub !== null &&
    row.acceptSignature !== null &&
    row.acceptedAt !== null
      ? {
          inviteeUserId: row.inviteeUserId,
          inviteeEncPubHex: row.inviteeEncPub,
          inviteeSigPubHex: row.inviteeSigPub,
          acceptSignatureHex: row.acceptSignature,
          acceptedAtMs: row.acceptedAt,
        }
      : null;
  return {
    id: row.id,
    projectId: row.projectId,
    tokenHashHex: row.tokenHash,
    role: row.role as InviteRole,
    inviterUserId: row.inviterUserId,
    status: row.status as InviteStatus,
    expiresAtMs: row.expiresAt,
    createdAtMs: row.createdAt,
    acceptance,
  };
}

/** pending / lookback の両上限を同一 INSERT 文で再評価する(deepsec S4)。 */
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
          tokenHash: sql<string>`${input.tokenHashHex}`.as("token_hash"),
          role: sql<string>`${input.role}`.as("role"),
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
 * 条件付き INSERT が 0 行だった理由を仕様順に導出する。拒否後の説明用だけで、
 * admission 自体は conditionalInviteInsert の 1 文が担う。
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
   * invite.* 監査行の INSERT…SELECT(AUDIT_SPEC §3.2 / §5.2)。直前の条件付き
   * UPDATE が 1 行に効いたときだけ挿入される(changes() ガード)。FROM は対象
   * 招待行そのもの(project_id を保存行から写す — ワイヤ申告値から組まない)。
   * org_id は載せない: invite.* の読み取り軸は org admin ではなくチェーン role
   * admin(AUDIT_SPEC §7)。
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
          // 共有列(audit.ts — recovery の取得計数と同じ写像)+ project_id は
          // 対象招待行から写す(ワイヤ申告値から組まない)
          ...guardedAuditSelectColumns(input),
          projectId: invitations.projectId,
        })
        .from(invitations)
        .where(and(eq(invitations.id, input.inviteId), sql`changes() = 1`)),
    );
  return {
    create: (input, nowMs, actor) =>
      run(async () => {
        // 判定と挿入を単一 INSERT…SELECT に畳む(deepsec S4)。別リクエストの
        // SELECT → INSERT では、並行した全員が同じ under-limit を観測して
        // 並行度ぶん上限を超えられる。audit は直前の INSERT が 1 行に効いた
        // ときだけ changes() ガードで書く
        const results = await db.batch([
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
        if (results[0].length === 1) {
          return { kind: "created" } as const;
        }
        const rejection = await inviteIssueRejection(db, input.projectId, nowMs);
        if (rejection !== null) {
          return rejection;
        }
        // conditional INSERT と説明用再読の間に revoke / expiry が進み、
        // 一時的に admission が再び可能になった稀な競合。新しいリクエストで
        // 安全に再試行できる型付き rate-limit に倒し、上限を破る fallback はしない
        return {
          kind: "rate-limited",
          retryAfterSeconds: 1,
        } as const;
      }),
    findByTokenHash: (tokenHashHex) =>
      run(() => findWhere(eq(invitations.tokenHash, tokenHashHex))),
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
// FlowSigningKeyRepo(AUTH_SPEC §4-2。CLI ログインのフロー署名鍵の置き場)
// ---------------------------------------------------------------------------

/** 署名鍵行の固定 id(高々 1 行)。 */
const FLOW_SIGNING_KEY_ID = "v1";

interface FlowSigningKeyRepoShape {
  /**
   * 初回使用時の自動生成(AUTH_SPEC §4-2 — セルフホストのセットアップ手順を
   * 増やさない)。冪等・先勝ち: 候補鍵を INSERT OR IGNORE し、常に保存行を
   * 読み戻す — 同時初回使用の 2 リクエストが別々の鍵を書き合って進行中
   * フローを失効させる分岐を閉じる。戻り値は勝った鍵(hex)。
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
          // INSERT OR IGNORE 直後の SELECT が空 = D1 障害(defect)
          throw new Error("flow signing key insert succeeded but the row is missing");
        }
        return row.keyHex;
      }),
  };
}

// ---------------------------------------------------------------------------
// CliFlowRepo(AUTH_SPEC §4-1 (4)〜(5)。CLI ログインのフロー行)
// ---------------------------------------------------------------------------

/**
 * デプロイメント全体の同時未消費フロー行の上限(AUTH_SPEC §4-1 (4) (iii)
 * 起草値)。到達には「既存アカウント × OAuth 完走」の同時併走が上限件数ぶん
 * 必要で安価に維持できない。TTL 15 分で自然回復。セルフホストの受理ポリシー
 * として調整可。
 */
export const MAX_CONCURRENT_CLI_FLOWS = 1000;

/**
 * 期限後も行を残す余裕(AUTH_SPEC §4-1 (5) 起草値 +5 分)。consumed / denied の
 * 行を flowToken の期限より先に消すと poll が「行なし = pending」と誤読して
 * CLI が完了済みフローを無限に待つ。日和見削除はこの余裕を過ぎた行のみ対象。
 */
const CLI_FLOW_DELETE_GRACE_MS = 5 * 60 * 1000;

/** フロー行の状態(§4-1 (4)〜(5) の CAS 語彙)。 */
type CliFlowStatus = "awaiting" | "approved" | "denied" | "consumed";

/** 承認ページの明示操作(§4-1 (4) (iv) — 承認 / 拒否の 2 択)。 */
type CliFlowDecision = "approved" | "denied";

interface NewCliLoginFlow {
  readonly flowId: string;
  readonly userId: string;
  readonly tokenName: string;
  readonly scopes: readonly TokenScope[];
  readonly expiresInDays: number;
  readonly userCode: string;
  /** 承認チケット(256-bit 乱数)の SHA-256(hex)。生値はページのみ。 */
  readonly ticketHash: string;
  readonly expiresAtMs: number;
}

/** poll の行引き(§4-1 (5))が見る形。ticket_hash は含めない(照合は CAS 内)。 */
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
 * create-or-match の帰結(§4-1 (4) (iii))。created / matched が承認ページの
 * 描画へ進む。rejected は一様エラーページ(別 user_id・期限切れ・終端状態 —
 * 理由を出し分けない)、capacity は上限到達(同じ一様エラーページ + 運用
 * アラートの材料)。
 */
type CliFlowAdmission = "created" | "matched" | "rejected" | "capacity";

interface CliFlowRepoShape {
  /**
   * フロー行の作成 CAS(create-or-match — §4-1 (4) (iii))。batch 先頭に期限 +
   * 余裕を過ぎた行の日和見削除を同梱し、作成は「同 flowId の行なし × 未消費
   * 総量が上限未満」の条件付き INSERT で行う。行が既にある場合、同一 user_id ×
   * awaiting × 期限内の再到達のみチケットを置換して成功(べき等 — matched)。
   * 別 user_id はチケットを回転させず rejected(乗っ取り・チケット失効攻撃の
   * 両経路を閉じる)。
   */
  readonly createOrMatch: (flow: NewCliLoginFlow, nowMs: number) => Effect.Effect<CliFlowAdmission>;
  /**
   * 承認 / 拒否の CAS(awaiting → approved | denied — §4-1 (4) (iv))。資格は
   * 承認チケット(最新 1 枚)で、不明・期限切れ・使用済みは一様に false。
   * 承認(user_id 確定)は `auth.login_succeeded`(authMethod cli_handoff —
   * §4-2)を changes() ガード付きで同一 batch に記録する。
   */
  readonly decideCas: (
    flowId: string,
    ticketHash: string,
    decision: CliFlowDecision,
    nowMs: number,
  ) => Effect.Effect<boolean>;
  /** poll の行引き(§4-1 (5))。行なし = null(呼び出し側が pending を導出)。 */
  readonly findById: (flowId: string) => Effect.Effect<CliLoginFlowRecord | null>;
  /**
   * 単回発行ゲート(approved → consumed の CAS — §4-1 (5))。勝者(true)だけが
   * PAT を発行する。CAS 成功後の発行失敗は consumed のまま終える(fail-closed —
   * 呼び出し側は巻き戻さない)。
   */
  readonly consumeCas: (flowId: string) => Effect.Effect<boolean>;
}

export class CliFlowRepo extends Context.Service<CliFlowRepo, CliFlowRepoShape>()("CliFlowRepo") {}

function makeCliFlowRepo(db: Db): CliFlowRepoShape {
  return {
    createOrMatch: (flow, nowMs) =>
      run(async () => {
        // 上限は未消費行(consumed 以外)で数える(§4-1 (4) (iii) の「同時未消費
        // 行」)。判定と挿入は同一 INSERT…SELECT(invites の admission と同型 —
        // 並行作成が同じ under-limit を観測して上限を超えない)
        const capAvailable = sql<boolean>`(
          select count(*) from ${cliLoginFlows}
          where ${cliLoginFlows.status} != 'consumed'
        ) < ${MAX_CONCURRENT_CLI_FLOWS}`;
        const rowAbsent = sql<boolean>`not exists (
          select 1 from ${cliLoginFlows} where ${cliLoginFlows.id} = ${flow.flowId}
        )`;
        const results = await db.batch([
          // 日和見削除(§4-1 (4) (iii)): 期限 + 余裕を過ぎた行のみ。consumed /
          // denied も余裕内は残す(poll の「行なし = pending」誤読の遮断)
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
        // 行あり(match / conflict)か上限到達。同一 user_id × awaiting × 期限内の
        // 再到達だけがチケットを置換して成功する(旧チケットは置換失効 — 有効な
        // チケットは常に最新 1 枚)。別 user_id はこの UPDATE に決して合致しない
        // = チケットを回転させない(§4-1 (4) (iii))
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
        // 行なし = 条件付き INSERT を落としたのは上限(capacity)。行あり =
        // 別 user_id / 期限切れ / terminal 状態(一様 rejected — 出し分けない)
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
          // 拒否は監査イベントを持たない(§4-2 — 承認 = login_succeeded のみ。
          // 失敗系は login_failed の固定窓規律で、明示拒否はどちらでもない)
          return (await cas).length === 1;
        }
        // 承認 = auth.login_succeeded(authMethod cli_handoff — §4-2)。actor の
        // user_id は行から写す(changes() ガード — invites の CAS と同型)
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
          // 自分の書き込み経路でしか生成されない列が壊れている = 実装バグ / DB 破損
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
// 束ね: D1 binding からリポジトリ一式の Context を作る
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
  | D1AuditRepo;

/** D1 binding からリポジトリサービス一式を構築する(worker 起動時に 1 回)。 */
export function makeDbServices(d1: D1Database): Context.Context<DbServices> {
  const db = drizzle(d1);
  return Context.make(IdentityRepo, makeIdentityRepo(db)).pipe(
    Context.add(SessionRepo, makeSessionRepo(db)),
    Context.add(TokenRepo, makeTokenRepo(db)),
    Context.add(OrgRepo, makeOrgRepo(db)),
    Context.add(ProjectRepo, makeProjectRepo(db)),
    Context.add(RecoveryRepo, makeRecoveryRepo(db)),
    Context.add(InviteRepo, makeInviteRepo(db)),
    Context.add(FlowSigningKeyRepo, makeFlowSigningKeyRepo(db)),
    Context.add(CliFlowRepo, makeCliFlowRepo(db)),
    Context.add(D1AuditRepo, makeD1AuditRepo(db)),
  );
}
