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
import { and, count, eq, isNull, lte, ne } from "drizzle-orm";
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
import type { D1AuditActor } from "./audit.ts";
import { D1AuditRepo, makeD1AuditRepo, orgAuditInsert, userAuditInsert } from "./audit.ts";
import {
  apiTokens,
  linkedIdentities,
  memberships,
  organizations,
  projects,
  recoveryWraps,
  sessions,
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
   * 同一 (user, name) の既存トークンを失効させつつ新トークンを挿入する
   * (device 交換の再発行 = ローテーション)。delete + insert を D1 の atomic
   * batch で行い、並行発行でも同名トークンが複数残らない(UNIQUE (user_id, name)
   * が最終防衛)。
   */
  readonly replaceForUserAndName: (token: NewApiToken) => Effect.Effect<void>;
  readonly findByHash: (tokenHash: string) => Effect.Effect<ApiTokenRecord | null>;
  readonly touchLastUsed: (id: string, nowMs: number) => Effect.Effect<void>;
  /** 明示失効。auth.token_revoked を同一 batch で記録する(AUDIT_SPEC §3.1)。 */
  readonly revokeById: (id: string, userId: string, nowMs: number) => Effect.Effect<void>;
  /** 指定名を除くユーザーのトークン本数(発行上限の判定用。同名は常にローテーション可)。 */
  readonly countByUserExcludingName: (userId: string, name: string) => Effect.Effect<number>;
}

export class TokenRepo extends Context.Service<TokenRepo, TokenRepoShape>()("TokenRepo") {}

function makeTokenRepo(db: Db): TokenRepoShape {
  return {
    // auth.token_created を同一 batch で記録する(AUDIT_SPEC §3.1)。同名旧行の
    // 削除はローテーションの一部で独立イベントにしない(旧トークン id を知る
    // には先行 SELECT が要り、発行の意味論も「置換」1 つで足りる)
    replaceForUserAndName: (token) =>
      run(async () => {
        await db.batch([
          db
            .delete(apiTokens)
            .where(and(eq(apiTokens.userId, token.userId), eq(apiTokens.name, token.name))),
          db.insert(apiTokens).values({
            id: token.id,
            userId: token.userId,
            name: token.name,
            tokenHash: token.tokenHash,
            tokenPrefix: token.tokenPrefix,
            scopes: JSON.stringify(token.scopes),
            expiresAt: null,
            createdAt: token.createdAtMs,
            lastUsedAt: null,
          }),
          userAuditInsert(db, token.createdAtMs, {
            event: "auth.token_created",
            actor: { userId: token.userId },
            payload: { tokenId: token.id, name: token.name, scopes: token.scopes },
          }),
        ]);
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
        await db.batch([
          db.delete(apiTokens).where(eq(apiTokens.id, id)),
          userAuditInsert(db, nowMs, {
            event: "auth.token_revoked",
            actor: { userId, apiTokenId: id },
            payload: { tokenId: id },
          }),
        ]);
      }),
    countByUserExcludingName: (userId, name) =>
      run(async () => {
        const row = await db
          .select({ n: count() })
          .from(apiTokens)
          .where(and(eq(apiTokens.userId, userId), ne(apiTokens.name, name)))
          .get();
        return row?.n ?? 0;
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
        const fetchedEvent = userAuditInsert(db, nowMs, {
          event: "auth.recovery_blob_fetched",
          actor,
        });
        const windowStart = row.fetchWindowStart;
        const windowExpired =
          windowStart === null || nowMs - windowStart >= RECOVERY_FETCH_WINDOW_MS;
        if (windowExpired) {
          await db.batch([
            db
              .update(recoveryWraps)
              .set({ fetchWindowStart: nowMs, fetchCount: 1 })
              .where(eq(recoveryWraps.userId, userId)),
            fetchedEvent,
          ]);
          return { allowed: true } as const;
        }
        if (row.fetchCount >= RECOVERY_FETCH_LIMIT) {
          const remainingMs = RECOVERY_FETCH_WINDOW_MS - (nowMs - windowStart);
          return {
            allowed: false,
            retryAfterSeconds: Math.max(1, Math.ceil(remainingMs / 1000)),
          } as const;
        }
        await db.batch([
          db
            .update(recoveryWraps)
            .set({ fetchCount: row.fetchCount + 1 })
            .where(eq(recoveryWraps.userId, userId)),
          fetchedEvent,
        ]);
        return { allowed: true } as const;
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
// ProjectRepo(§11-3。org 帰属メタデータ。権限テーブルではない)
// ---------------------------------------------------------------------------

interface ProjectRepoShape {
  /**
   * 冪等挿入(修復経路を含む §11-3)。既存行はそのまま。org.project_created
   * (AUDIT_SPEC §3.2)を同一 batch で記録する。batch の原子性により、既存行
   * との競合で挿入が成立しなかった場合は監査行も巻き戻る(空振り挿入で
   * イベントだけ重複しない)。
   */
  readonly insertIfAbsent: (
    projectId: string,
    orgId: string,
    nowMs: number,
    actor: D1AuditActor,
  ) => Effect.Effect<void>;
  readonly exists: (projectId: string) => Effect.Effect<boolean>;
}

export class ProjectRepo extends Context.Service<ProjectRepo, ProjectRepoShape>()("ProjectRepo") {}

function makeProjectRepo(db: Db): ProjectRepoShape {
  return {
    insertIfAbsent: (projectId, orgId, nowMs, actor) =>
      run(async () => {
        try {
          await db.batch([
            db.insert(projects).values({ id: projectId, orgId, createdAt: nowMs }),
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
    Context.add(D1AuditRepo, makeD1AuditRepo(db)),
  );
}
