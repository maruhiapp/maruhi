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
  ResolvedUser,
  SessionRecord,
  UserOrg,
  VerifiedIdentity,
} from "../auth-domain.ts";
import { ulid } from "../ids.ts";
import {
  apiTokens,
  linkedIdentities,
  memberships,
  organizations,
  projects,
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
 */
function createUserBatch(
  db: Db,
  identity: VerifiedIdentity,
  nowMs: number,
): Effect.Effect<string, InsertConflictError> {
  const userId = ulid(nowMs);
  const orgId = ulid(nowMs);
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
  readonly deleteByHash: (idHash: string) => Effect.Effect<void>;
  /** 期限切れ行の一括掃除(cron から呼ぶ。提示されない行はここでしか消えない)。 */
  readonly deleteExpired: (nowMs: number) => Effect.Effect<void>;
}

export class SessionRepo extends Context.Service<SessionRepo, SessionRepoShape>()("SessionRepo") {}

function makeSessionRepo(db: Db): SessionRepoShape {
  return {
    insert: (idHash, userId, authMethod, nowMs, expiresAtMs) =>
      run(async () => {
        await db.insert(sessions).values({
          id: idHash,
          userId,
          authMethod,
          createdAt: nowMs,
          expiresAt: expiresAtMs,
          lastUsedAt: nowMs,
        });
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
  readonly deleteById: (id: string) => Effect.Effect<void>;
  /** 指定名を除くユーザーのトークン本数(発行上限の判定用。同名は常にローテーション可)。 */
  readonly countByUserExcludingName: (userId: string, name: string) => Effect.Effect<number>;
}

export class TokenRepo extends Context.Service<TokenRepo, TokenRepoShape>()("TokenRepo") {}

function makeTokenRepo(db: Db): TokenRepoShape {
  return {
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
        ]);
      }),
    findByHash: (tokenHash) => run(() => findTokenByHash(db, tokenHash)),
    touchLastUsed: (id, nowMs) =>
      run(async () => {
        await db.update(apiTokens).set({ lastUsedAt: nowMs }).where(eq(apiTokens.id, id));
      }),
    deleteById: (id) =>
      run(async () => {
        await db.delete(apiTokens).where(eq(apiTokens.id, id));
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
  /** 冪等挿入(修復経路を含む §11-3)。既存行はそのまま。 */
  readonly insertIfAbsent: (projectId: string, orgId: string, nowMs: number) => Effect.Effect<void>;
  readonly exists: (projectId: string) => Effect.Effect<boolean>;
}

export class ProjectRepo extends Context.Service<ProjectRepo, ProjectRepoShape>()("ProjectRepo") {}

function makeProjectRepo(db: Db): ProjectRepoShape {
  return {
    insertIfAbsent: (projectId, orgId, nowMs) =>
      run(async () => {
        await db
          .insert(projects)
          .values({ id: projectId, orgId, createdAt: nowMs })
          .onConflictDoNothing();
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

export type DbServices = IdentityRepo | SessionRepo | TokenRepo | OrgRepo | ProjectRepo;

/** D1 binding からリポジトリサービス一式を構築する(worker 起動時に 1 回)。 */
export function makeDbServices(d1: D1Database): Context.Context<DbServices> {
  const db = drizzle(d1);
  return Context.make(IdentityRepo, makeIdentityRepo(db)).pipe(
    Context.add(SessionRepo, makeSessionRepo(db)),
    Context.add(TokenRepo, makeTokenRepo(db)),
    Context.add(OrgRepo, makeOrgRepo(db)),
    Context.add(ProjectRepo, makeProjectRepo(db)),
  );
}
