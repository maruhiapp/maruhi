// D1 側監査ログの追記と読み取り(AUDIT_SPEC §3.1〜§3.2 / §5.2 案 A / §7)。
//
// - append-only(§1-4): この層は追記と読み取りのみを公開する(更新・削除の
//   口を作らない)
// - 主データ書き込みと同一トランザクションでの追記(§5.2 の採用理由 (2))は、
//   各リポジトリが自分の batch へ挿入文(userAuditInsert / orgAuditInsert)を
//   同梱することで実現する。単独追記(login_failed 等、主データ書き込みを
//   伴わないイベント)だけが D1AuditRepo を使う
// - 読み取り(§7 — C1)は invite.* の project_id スコープ(権限軸は worker が
//   チェーン role admin で強制)と user 系の本人軸のみ。org admin 軸は org 管理
//   API の導入時に同時実装する(C1 裁定)
// - アイデンティティ規則(§1-2): actor / target は内部 user_id(+ maruhi 発行
//   トークン id)と auth_method 種別名のみ。プロバイダ ID・login・メールを
//   この層に持ち込まないこと

import type { AuditActor } from "@maruhi/core";
import { auditPayloadWith } from "@maruhi/core";
import { and, count, desc, eq, gte, inArray, isNull, lt, or, type SQL, sql } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import { randomHex } from "../ids.ts";
import { orgAuditEvents, userAuditEvents } from "./schema.ts";

type Db = ReturnType<typeof drizzle>;

/**
 * 監査アクター(AUDIT_SPEC §2)。共有の AuditActor(@maruhi/core — 認証主体
 * からの写像 auditActorOf の唯一の出口)からの派生で、userId のみ省略可にする:
 * 省略は「未認証の外部主体」(auth.login_failed のみ — 人はいるが特定できて
 * いない。type=system は主体のない内部処理用であり、外部からの失敗試行には
 * 使わない)。
 */
export type D1AuditActor = Omit<AuditActor, "userId"> & { readonly userId?: string };

/** 監査イベント 1 行の入力(列は schema.ts の共通列。未指定は NULL)。 */
export interface D1AuditEventInput {
  readonly event: string;
  readonly actor: D1AuditActor;
  readonly targetUserId?: string;
  readonly orgId?: string;
  readonly projectId?: string;
  readonly payload?: Readonly<Record<string, unknown>>;
}

/** 挿入行への写像。auth_method は DO 側と同じく payload に載る(§2)。 */
function rowOf(event: D1AuditEventInput, serverTs: number) {
  const payload = auditPayloadWith(event.actor, event.payload);
  return {
    // ワイヤ行識別子(AUDIT_SPEC §5.1 row_id — §7 の不透明カーソル)
    rowId: randomHex(16),
    serverTs,
    event: event.event,
    actorType: "user",
    actorUserId: event.actor.userId ?? null,
    actorApiTokenId: event.actor.apiTokenId ?? null,
    targetUserId: event.targetUserId ?? null,
    orgId: event.orgId ?? null,
    projectId: event.projectId ?? null,
    payload: Object.keys(payload).length === 0 ? null : JSON.stringify(payload),
  };
}

/** 認証系イベント(§3.1)の挿入文。リポジトリの batch に同梱する。 */
export function userAuditInsert(db: Db, serverTs: number, event: D1AuditEventInput) {
  return db.insert(userAuditEvents).values(rowOf(event, serverTs));
}

/** org 系イベント(§3.2)の挿入文。リポジトリの batch に同梱する。 */
export function orgAuditInsert(db: Db, serverTs: number, event: D1AuditEventInput) {
  return db.insert(orgAuditEvents).values(rowOf(event, serverTs));
}

/**
 * auth.login_failed の記録上限(AUDIT_SPEC §3.1)。login_failed は唯一の
 * 未認証経路からの D1 書き込みであり、無効リクエストの洪水による書き込み増幅
 * (可用性・コスト面の攻撃)を有界にするため、固定窓の全体上限を超えた分は
 * 記録しない。読み → 書きの 2 文で、並行リクエスト下では僅かに超過しうる
 * ベストエフォート(recovery の取得計数 — repos.ts — と同じ性質)。
 */
export const LOGIN_FAILED_WINDOW_MS = 60 * 60 * 1000;
export const LOGIN_FAILED_WINDOW_LIMIT = 100;

// ---------------------------------------------------------------------------
// 読み取り面(AUDIT_SPEC §7 — C1)。seq カーソルページング(新しい順)。
// ---------------------------------------------------------------------------

/**
 * ページ指定(seq 降順)。beforeRowId は前ページ末尾行の row_id(§7 の不透明
 * カーソル)。解決は各読み取りの可視性述語つきで行い、述語外・不明な id は
 * 空ページとして振る舞う(存在オラクルにしない)。
 */
interface D1AuditReadPage {
  readonly beforeRowId: string | null;
  readonly limit: number;
}

/** D1 監査行の読み取り形(共通列のうち C1 の応答が運ぶもの。NULL は null)。 */
export interface D1StoredAuditEventRow {
  readonly seq: number;
  /**
   * ワイヤ行識別子(row_id)。NULL 観測時の遅延 backfill により原則常在
   * (補填と再読の間に旧コードが並行挿入する極小レースのみ空文字列 —
   * その要求は encode 失敗しうるが次の読み取りが再補填する)。
   */
  readonly rowId: string;
  readonly serverTs: number;
  readonly event: string;
  readonly actorType: string;
  readonly actorUserId: string | null;
  readonly actorApiTokenId: string | null;
  readonly targetUserId: string | null;
  readonly orgId: string | null;
  readonly projectId: string | null;
  readonly payload: Readonly<Record<string, unknown>> | null;
}

/** invite ライフサイクルのイベント名(§3.2)。org 系イベントを混入させない。 */
export const INVITE_AUDIT_EVENTS = ["invite.created", "invite.accepted", "invite.revoked"] as const;

interface D1AuditRepoShape {
  /** 単独イベントの追記(主データ書き込みを伴わないイベント用)。 */
  readonly appendUserEvent: (event: D1AuditEventInput, serverTs: number) => Effect.Effect<void>;
  /**
   * auth.login_failed 専用の追記。固定窓(1 時間)の記録上限を超えたら黙って
   * 落とす(SHOULD 記録 — 洪水そのものは窓内の上限到達として観測できる)。
   */
  readonly appendLoginFailed: (event: D1AuditEventInput, serverTs: number) => Effect.Effect<void>;
  /**
   * invite.* の project_id スコープ読み取り(§7 の例外規定)。権限軸(当該
   * プロジェクトのチェーン role admin 以上 × トークンスコープ admin)は
   * worker 側ハンドラが強制する — この層は述語のみを持つ。
   */
  readonly readProjectInviteEvents: (
    projectId: string,
    page: D1AuditReadPage,
  ) => Effect.Effect<readonly D1StoredAuditEventRow[]>;
  /**
   * user 系(§3.1)の本人軸読み取り(§6: 本人のみ)。actor または target が
   * 本人の行だけを返す。auth.login_failed は actor user_id を持たない(§3.1)
   * ため、どの本人軸にも現れない(運営者ビューの領分 — L-4)。
   */
  readonly readUserEventsFor: (
    userId: string,
    page: D1AuditReadPage,
  ) => Effect.Effect<readonly D1StoredAuditEventRow[]>;
}

export class D1AuditRepo extends Context.Service<D1AuditRepo, D1AuditRepoShape>()("D1AuditRepo") {}

/** payload 列(JSON)の防御的 parse(壊れた行は null 扱い — 読み取りを defect にしない)。 */
function parseStoredPayload(value: string | null): Readonly<Record<string, unknown>> | null {
  if (value === null) {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(value);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

type D1AuditTable = typeof userAuditEvents | typeof orgAuditEvents;

/**
 * row_id の遅延 backfill。マイグレーション(20260816030340)の backfill 後も、
 * デプロイ間隙(`db:migrate` 適用後・旧 worker 稼働中、およびロールバック時)に
 * 旧コードが row_id なしの行を書く窓が残る。その行をワイヤへ出すと `id` の
 * Schema encode が失敗して読み取りが恒久 500 になる(pullfrog 指摘)ため、
 * NULL 行を観測した読み取りだけがマイグレーションと同一の文を冪等に再適用する
 * (無条件に走らせると、全テナント共有の D1 writer に監査読み取りのたびに
 * 書き込みが乗る — 同指摘のフォローアップ)。監査内容の列には触れない
 * (§1-4 の append-only は内容の不変性 — row_id はサーバー採番の合成識別子で、
 * この補填は §5.1 backfill の繰り延べにすぎない)。randomblob は行ごとに評価
 * され、WHERE row_id IS NULL は一意索引の NULL エントリを seek する。
 */
async function backfillMissingRowIds(db: Db, table: D1AuditTable): Promise<void> {
  await db
    .update(table)
    .set({ rowId: sql`lower(hex(randomblob(16)))` })
    .where(isNull(table.rowId));
}

/** selectAuditPage の生 1 回分の読み(rowId は補填前なら NULL がありうる)。 */
async function readAuditPageRows(
  db: Db,
  table: D1AuditTable,
  predicate: SQL | undefined,
  page: D1AuditReadPage,
): Promise<
  readonly (Omit<D1StoredAuditEventRow, "rowId" | "payload"> & {
    readonly rowId: string | null;
    readonly payload: string | null;
  })[]
> {
  let where = predicate;
  if (page.beforeRowId !== null) {
    const cursor = await db
      .select({ seq: table.seq })
      .from(table)
      .where(and(predicate, eq(table.rowId, page.beforeRowId)))
      .get();
    if (cursor === undefined) {
      return [];
    }
    where = and(predicate, lt(table.seq, cursor.seq));
  }
  return db
    .select({
      seq: table.seq,
      rowId: table.rowId,
      serverTs: table.serverTs,
      event: table.event,
      actorType: table.actorType,
      actorUserId: table.actorUserId,
      actorApiTokenId: table.actorApiTokenId,
      targetUserId: table.targetUserId,
      // org_id は本 PR の 2 経路では常に NULL(invite.* は意図的に持たず、
      // user 系に書き手がいない)が、この helper は両テーブル汎用であり、
      // 将来の org admin 軸で黙って欠落しないよう射影から落とさない
      orgId: table.orgId,
      projectId: table.projectId,
      payload: table.payload,
    })
    .from(table)
    .where(where)
    .orderBy(desc(table.seq))
    .limit(page.limit);
}

/**
 * ページ条件(seq 降順 + row_id カーソル)を述語に合成して読む。カーソルの
 * row_id → seq 解決は**同じ可視性述語つき**で行う(述語外の行の id を差しても
 * 「不明」と同一 = 空ページ。存在オラクルにしない — AUDIT_SPEC §7)。
 * row_id が NULL の行(デプロイ間隙の旧コード書き込み)をページ内に観測した
 * ときだけ遅延 backfill を実行して読み直す — 定常状態の読み取りは純粋な
 * 読み取りのまま。カーソルは常に過去ページが返した非 NULL の row_id なので、
 * カーソル解決が補填前の状態で失敗することはない。
 */
async function selectAuditPage(
  db: Db,
  table: D1AuditTable,
  predicate: SQL | undefined,
  page: D1AuditReadPage,
): Promise<readonly D1StoredAuditEventRow[]> {
  let rows = await readAuditPageRows(db, table, predicate, page);
  if (rows.some((row) => row.rowId === null)) {
    await backfillMissingRowIds(db, table);
    rows = await readAuditPageRows(db, table, predicate, page);
  }
  return rows.map((row) => ({
    ...row,
    // 補填後の再読でも、補填と再読の間に旧 worker が書いた行は NULL であり
    // うる(極小レース)。その要求の encode は失敗しうるが、次の読み取りが
    // 再度補填する — fallback は型の絞り込み + この残余のためのもの
    rowId: row.rowId ?? "",
    payload: parseStoredPayload(row.payload),
  }));
}

export function makeD1AuditRepo(db: Db): D1AuditRepoShape {
  return {
    appendUserEvent: (event, serverTs) =>
      Effect.promise(async () => {
        await userAuditInsert(db, serverTs, event);
      }),
    appendLoginFailed: (event, serverTs) =>
      Effect.promise(async () => {
        const row = await db
          .select({ n: count() })
          .from(userAuditEvents)
          .where(
            and(
              eq(userAuditEvents.event, "auth.login_failed"),
              gte(userAuditEvents.serverTs, serverTs - LOGIN_FAILED_WINDOW_MS),
            ),
          )
          .get();
        if ((row?.n ?? 0) >= LOGIN_FAILED_WINDOW_LIMIT) {
          return;
        }
        await userAuditInsert(db, serverTs, event);
      }),
    readProjectInviteEvents: (projectId, page) =>
      Effect.promise(() =>
        selectAuditPage(
          db,
          orgAuditEvents,
          // イベント名の絞りは invite.* のみ(§7): 同じ project_id を持つ org 系
          // イベント(org.project_created 等)は org admin 軸の領分であり、
          // プロジェクト監査の経路に混入させない
          and(
            eq(orgAuditEvents.projectId, projectId),
            inArray(orgAuditEvents.event, [...INVITE_AUDIT_EVENTS]),
          ),
          page,
        ),
      ),
    readUserEventsFor: (userId, page) =>
      Effect.promise(() =>
        selectAuditPage(
          db,
          userAuditEvents,
          or(eq(userAuditEvents.actorUserId, userId), eq(userAuditEvents.targetUserId, userId)),
          page,
        ),
      ),
  };
}
