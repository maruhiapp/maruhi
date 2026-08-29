// D1 リポジトリの Effect サービス実装(AUTH_SPEC §2。ADR-0006)。
//
// - Drizzle の型・クエリはこのファイル(db.package 境界内)に閉じる。公開シェイプは
//   ドメイン型(../auth-domain.ts)と Effect のみ
// - D1 の障害(接続・SQL エラー)は defect として扱う(Effect.promise)。ドメイン上
//   予期される分岐(該当なし・一意制約競合)だけを値で表現する
// - Drizzle 採用の確定判断はセッション 06: classic drizzle-orm/d1 を採用。
//   effect-d1 ドライバは rc.4 時点で transaction / batch 未対応のため、原子性が
//   必要な getOrCreateUser(§1-5)が成立しない。D1 の atomic batch を使う

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
  RecoveryFetchDecision,
  RecoveryWrapRecord,
  ResolvedUser,
  SessionRecord,
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
  invitations,
  linkedIdentities,
  memberships,
  organizations,
  orgAuditEvents,
  projectMembers,
  projects,
  recoveryWraps,
  sessions,
  userAuditEvents,
  users,
} from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

const run = <T>(evaluate: () => Promise<T>): Effect.Effect<T> => Effect.promise(evaluate);

// ---------------------------------------------------------------------------
// IdentityRepo(§1-5 getOrCreateUser / §9-1 パーソナル org 自動作成)
// ---------------------------------------------------------------------------

interface IdentityRepoShape {
  /** 単一の冪等な入口。新規作成時は本人 owner のパーソナル org を同時に作る。 */
  readonly getOrCreateUser: (
    identity: VerifiedIdentity,
    nowMs: number,
  ) => Effect.Effect<ResolvedUser>;
  /** ユーザーが属する org 一覧(プロジェクト作成先の発見用。§11-3)。 */
  readonly listUserOrgs: (userId: string) => Effect.Effect<readonly UserOrg[]>;
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

/**
 * users + linked_identities + パーソナル org + owner membership を atomic batch で
 * 作成する。並行サインアップは (provider, provider_user_id) の PK で片方が失敗する
 * ので、競合時は呼び出し側が再ルックアップする。競合以外の失敗は defect。
 *
 * 監査(AUDIT_SPEC §3.1〜§3.2)も同じ batch で追記する: auth.user_created /
 * auth.identity_linked(provider 種別名のみ — 数値 ID・login は記録しない)/
 * org.created(パーソナル org 自動作成。org 名は providerLogin 由来のため
 * payload に写さない — §1-2)/ org.member_added(owner 自身)。
 */
function createUserBatch(
  db: Db,
  identity: VerifiedIdentity,
  nowMs: number,
): Effect.Effect<string, InsertConflictError> {
  const userId = ulid(nowMs);
  const orgId = ulid(nowMs);
  const actor: D1AuditActor = { userId };
  return Effect.tryPromise({
    try: async () => {
      await db.batch([
        db.insert(users).values({
          id: userId,
          email: identity.verifiedEmail,
          emailVerified: identity.verifiedEmail === null ? 0 : 1,
          createdAt: nowMs,
          updatedAt: nowMs,
        }),
        db.insert(linkedIdentities).values({
          userId,
          provider: identity.provider,
          providerUserId: identity.providerUserId,
          providerLogin: identity.providerLogin,
          linkedAt: nowMs,
        }),
        db.insert(organizations).values({
          id: orgId,
          slug: `u-${userId.toLowerCase()}`,
          name: identity.providerLogin ?? "personal",
          createdAt: nowMs,
        }),
        db.insert(memberships).values({ orgId, userId, role: "owner" }),
        userAuditInsert(db, nowMs, { event: "auth.user_created", actor }),
        userAuditInsert(db, nowMs, {
          event: "auth.identity_linked",
          actor,
          payload: { provider: identity.provider },
        }),
        orgAuditInsert(db, nowMs, {
          event: "org.created",
          actor,
          orgId,
          payload: { personal: true },
        }),
        orgAuditInsert(db, nowMs, {
          event: "org.member_added",
          actor,
          orgId,
          targetUserId: userId,
          payload: { role: "owner" },
        }),
      ]);
      return userId;
    },
    catch: (error) => {
      if (isUniqueConflict(error)) {
        return new InsertConflictError();
      }
      // 競合以外の D1 障害はインフラ defect としてそのまま伝播する
      throw error;
    },
  });
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

function makeIdentityRepo(db: Db): IdentityRepoShape {
  const getOrCreateUser = (
    identity: VerifiedIdentity,
    nowMs: number,
  ): Effect.Effect<ResolvedUser> =>
    Effect.flatMap(lookupLinkedUser(db, identity), (existing) => {
      if (existing !== null) {
        return Effect.as(refreshVerifiedEmail(db, existing, identity, nowMs), {
          userId: existing,
          created: false,
        } satisfies ResolvedUser);
      }
      return createUserBatch(db, identity, nowMs).pipe(
        Effect.map((userId): ResolvedUser => ({ userId, created: true })),
        Effect.catchTag("InsertConflict", () => rerunLookup(db, identity)),
      );
    });
  return { getOrCreateUser, listUserOrgs: (userId) => listUserOrgs(db, userId) };
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
  /** 明示失効。id × user 所有を強制し、auth.token_revoked を記録する(§3.1 / S8)。 */
  readonly revokeById: (id: string, userId: string, nowMs: number) => Effect.Effect<void>;
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
          expiresAt: sql<number | null>`${null}`.as("expires_at"),
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
    // v1 の失効経路は「提示されたトークン自身」のみ(AUTH_SPEC §6)なので、
    // actor のトークン id = 失効対象 id になる
    revokeById: (id, userId, nowMs) =>
      run(async () => {
        // 削除の成立を returning で観測してからイベントを書く(revokeByHash と
        // 同型 — Cursor Security Agent 指摘対応)。並行 revoke は呼び出し側の
        // findByHash を両方通過し得るため、無条件 batch だと 1 失効に複数の
        // token_revoked を記録できてしまう(過大計上)。重複より欠落側に倒す
        const deleted = await db
          .delete(apiTokens)
          // deepsec S8: id だけで消すと将来 token-id 指定の管理 API が増えた際に
          // 別 user の token を失効し、監査 actor だけ呼び出し user と誤記録する。
          // 現行 caller も server-derived userId を渡すが、所有条件は repo 境界で強制
          .where(and(eq(apiTokens.id, id), eq(apiTokens.userId, userId)))
          .returning({ id: apiTokens.id });
        if (deleted.length === 0) {
          return;
        }
        await userAuditInsert(db, nowMs, {
          event: "auth.token_revoked",
          actor: { userId, apiTokenId: id },
          payload: { tokenId: id },
        });
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
    Context.add(D1AuditRepo, makeD1AuditRepo(db)),
  );
}
