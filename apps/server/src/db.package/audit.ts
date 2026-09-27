// D1 側監査ログの追記と読み取り(AUDIT_SPEC §3.1〜§3.2 / §5.2 案 A / §7)。
//
// - append-only(§1-4): この層は追記と読み取りのみを公開する(更新・削除の
//   口を作らない)
// - 主データ書き込みと同一トランザクションでの追記(§5.2 の採用理由 (2))は、
//   各リポジトリが自分の batch へ挿入文(userAuditInsert / orgAuditInsert)を
//   同梱することで実現する。単独追記(login_failed 等、主データ書き込みを
//   伴わないイベント)だけが D1AuditRepo を使う
// - 読み取り(§7)は invite.* の project_id スコープ(権限軸は worker が
//   チェーン role admin で強制)と user 系の本人軸のみ。org admin 軸は org 管理
//   API の導入時に同時実装する
// - アイデンティティ規則(§1-2): actor / target は内部 user_id(+ maruhi 発行
//   トークン id)と auth_method 種別名のみ。プロバイダ ID・login・メールを
//   この層に持ち込まないこと

import type { AuditActor } from "@maruhi/core";
import { auditPayloadWith } from "@maruhi/core";
import { and, desc, eq, inArray, lt, or, type SQL, sql } from "drizzle-orm";
import type { drizzle } from "drizzle-orm/d1";
import { Context, Effect } from "effect";

import { randomHex } from "../ids.ts";
import { loginFailedWindows, orgAuditEvents, userAuditEvents } from "./schema.ts";

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

/**
 * `changes() = 1` ガード付き INSERT…SELECT(AUDIT_SPEC §5.2 — 直前の条件付き
 * UPDATE が効いたときだけ監査行を挿入する)用の共有選択列。rowOf と同じ列写像の
 * SELECT 版 — 呼び出し側(invites の CAS・recovery の取得計数)が列リストを
 * 個別に書き写すと、行形状の変更時に黙って食い違う。
 * FROM・WHERE(ガード条件)と追加列(invites の project_id)は呼び出し側が持つ。
 */
export function guardedAuditSelectColumns(input: {
  readonly event: string;
  readonly actor: D1AuditActor;
  readonly nowMs: number;
  readonly targetUserId?: string | null;
  readonly payload?: Readonly<Record<string, unknown>>;
  /** 保存行から組む動的 payload。指定時は静的 payload より優先する。 */
  readonly payloadSql?: SQL<string | null>;
}) {
  const payload = auditPayloadWith(input.actor, input.payload);
  const payloadSql =
    input.payloadSql ??
    sql<string | null>`${Object.keys(payload).length === 0 ? null : JSON.stringify(payload)}`;
  return {
    // ワイヤ行識別子(AUDIT_SPEC §5.1 row_id)。ガード付き挿入は高々 1 行なので、
    // 文の構築時に採番した定数で足りる
    rowId: sql<string>`${randomHex(16)}`.as("row_id"),
    serverTs: sql<number>`${input.nowMs}`.as("server_ts"),
    event: sql<string>`${input.event}`.as("event"),
    actorType: sql<string>`'user'`.as("actor_type"),
    actorUserId: sql<string | null>`${input.actor.userId ?? null}`.as("actor_user_id"),
    actorApiTokenId: sql<string | null>`${input.actor.apiTokenId ?? null}`.as("actor_api_token_id"),
    targetUserId: sql<string | null>`${input.targetUserId ?? null}`.as("target_user_id"),
    payload: payloadSql.as("payload"),
  };
}

/** org 系イベント(§3.2)の挿入文。リポジトリの batch に同梱する。 */
export function orgAuditInsert(db: Db, serverTs: number, event: D1AuditEventInput) {
  return db.insert(orgAuditEvents).values(rowOf(event, serverTs));
}

/**
 * auth.login_failed の記録上限(AUDIT_SPEC §3.1)。login_failed は唯一の
 * 未認証経路からの D1 書き込みであり、無効リクエストの洪水による書き込み増幅
 * (可用性・コスト面の攻撃)を有界にするため、固定窓の上限を超えた分は
 * 記録しない。上限は `auth_method + reason` 単位のバケットで数える:
 * 単一枠や method だけの枠だと、別経路・別理由の洪水が
 * 標的型失敗の reason まで消してしまう。
 */
export const LOGIN_FAILED_WINDOW_MS = 60 * 60 * 1000;
export const LOGIN_FAILED_WINDOW_LIMIT = 100;

interface LoginFailedBucket {
  readonly authMethod: string;
  readonly reason: string;
}

/** mutable counter の主キー。外部 ID / IP は含めず、監査行が持つ分類だけを使う。 */
function loginFailedBucketKey(bucket: LoginFailedBucket): string {
  return JSON.stringify([bucket.authMethod, bucket.reason]);
}

/**
 * 上限到達の窓に残す集約マーカー(AUDIT_SPEC §3.1)。抑制が
 * **起きたこと**に加えて**量**も観測可能にするため、バケットの抑制件数が 10 の
 * 冪(1・10・100・…)に達した時点で 1 行残す — 書き込みは抑制件数に対して対数的
 * (洪水下でも窓あたり数行)。個別行と同じく actor は user_id なしの type=user
 * (外部 provider ID・IP を append-only actor に書かない — §1-2)。
 */
const LOGIN_FAILED_SUPPRESSED_EVENT = "auth.login_failed_suppressed";

/**
 * auth.signup_denied の抑制マーカー(AUDIT_SPEC §3.1)。
 * login_failed と同じ固定窓・10 の冪規律で、バケットはイベント名 + reason。
 */
const SIGNUP_DENIED_SUPPRESSED_EVENT = "auth.signup_denied_suppressed";

/** 抑制マーカーを残す件数か(1・10・100・… — 上の doc)。 */
function isSuppressionMilestone(suppressedCount: number): boolean {
  if (suppressedCount < 1) {
    return false;
  }
  // 10 進の桁上がりちょうどか(log10 の丸め誤差を避けて整数の割り算で判定する)
  let remaining = suppressedCount;
  while (remaining % 10 === 0) {
    remaining /= 10;
  }
  return remaining === 1;
}

// ---------------------------------------------------------------------------
// 読み取り面(AUDIT_SPEC §7)。seq カーソルページング(新しい順)。
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

/** D1 監査行の読み取り形(共通列のうち §7 の応答が運ぶもの。NULL は null)。 */
export interface D1StoredAuditEventRow {
  readonly seq: number;
  /** ワイヤ行識別子(row_id — 16 バイト乱数 hex)。 */
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
   * auth.login_failed 専用の追記。固定窓(1 時間)の記録上限を超えたら個別行は
   * 落とし、抑制マーカーだけ残す(SHOULD 記録 — AUDIT_SPEC §3.1)。
   *
   * `bucket` は上限を数える単位(auth_method + reason)。
   * 発信元識別子を渡さないこと(§1-2 の線引き。理由は §3.1)。
   */
  readonly appendLoginFailed: (
    event: D1AuditEventInput,
    serverTs: number,
    bucket: LoginFailedBucket,
  ) => Effect.Effect<void>;
  /**
   * auth.signup_denied 専用の追記(AUDIT_SPEC §3.1)。
   * login_failed と同じ固定窓上限規律で、バケットは reason 単位(拒否理由ごとに
   * 独立の枠 — 別理由の洪水が標的型の拒否まで消さない)。提示された外部
   * provider ID を渡さないこと(§1-2)。
   */
  readonly appendSignupDenied: (
    event: D1AuditEventInput,
    serverTs: number,
    reason: string,
  ) => Effect.Effect<void>;
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

/** selectAuditPage の生 1 回分の読み。 */
async function readAuditPageRows(
  db: Db,
  table: D1AuditTable,
  predicate: SQL | undefined,
  page: D1AuditReadPage,
): Promise<
  readonly (Omit<D1StoredAuditEventRow, "payload"> & {
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
 */
async function selectAuditPage(
  db: Db,
  table: D1AuditTable,
  predicate: SQL | undefined,
  page: D1AuditReadPage,
): Promise<readonly D1StoredAuditEventRow[]> {
  const rows = await readAuditPageRows(db, table, predicate, page);
  return rows.map((row) => ({ ...row, payload: parseStoredPayload(row.payload) }));
}

/**
 * 固定窓上限つきの未認証イベント追記(AUDIT_SPEC §3.1 — auth.login_failed と
 * auth.signup_denied の共通機構)。
 *
 * 窓の計数は監査ログの走査ではなく専用カウンタ行で行う:
 * append-only で伸び続ける user_audit_events を未認証経路の追記ごとに走査すると、
 * 有界にしたい洪水そのものがコスト増幅器になる。窓のリセット・加算・上限判定は
 * 1 文の条件付き UPSERT に畳み、RETURNING の新しい計数から判定を導く
 * (recovery 取得計数 — repos.ts — と同じ形)。カウンタテーブルは
 * loginFailedWindows を共有する(bucketKey が名前空間を分ける — 監査行ではない
 * 可変状態であり、テーブル名は導入時イベントの歴史名)。
 */
async function appendWithFixedWindow(
  db: Db,
  event: D1AuditEventInput,
  serverTs: number,
  spec: {
    readonly bucketKey: string;
    readonly markerEvent: string;
    /** マーカー payload の分類部(窓長・上限・抑制件数はここで足す)。 */
    readonly markerBasePayload: Readonly<Record<string, unknown>>;
  },
): Promise<void> {
  const expired = sql`${serverTs} - ${loginFailedWindows.windowStart} >= ${LOGIN_FAILED_WINDOW_MS}`;
  const underLimit = sql`${loginFailedWindows.recordedCount} < ${LOGIN_FAILED_WINDOW_LIMIT}`;
  const counted = await db
    .insert(loginFailedWindows)
    .values({
      bucket: spec.bucketKey,
      windowStart: serverTs,
      recordedCount: 1,
      suppressedCount: 0,
    })
    .onConflictDoUpdate({
      target: loginFailedWindows.bucket,
      set: {
        windowStart: sql`case when ${expired} then ${serverTs} else ${loginFailedWindows.windowStart} end`,
        recordedCount: sql`case when ${expired} then 1 when ${underLimit} then ${loginFailedWindows.recordedCount} + 1 else ${loginFailedWindows.recordedCount} end`,
        suppressedCount: sql`case when ${expired} then 0 when ${underLimit} then ${loginFailedWindows.suppressedCount} else ${loginFailedWindows.suppressedCount} + 1 end`,
      },
    })
    .returning({
      recordedCount: loginFailedWindows.recordedCount,
      suppressedCount: loginFailedWindows.suppressedCount,
    })
    .get();
  // 窓内では recorded が上限まで伸びてから suppressed が伸びる(両方が
  // 同時に進むことはない)。よって「上限に達していて、かつ抑制が 1 件以上」
  // が抑制されたリクエストの十分条件になる — 上限ちょうどの**最後の許可**は
  // suppressed = 0 のまま通る
  const recorded = counted?.recordedCount ?? 1;
  const suppressed = counted?.suppressedCount ?? 0;
  if (recorded >= LOGIN_FAILED_WINDOW_LIMIT && suppressed >= 1) {
    // 個別行は落とすが、抑制を黙って行わない: 抑制件数が
    // 10 の冪に達した時点でマーカーを 1 行残す。行の密度と最後の件数から
    // 抑制の規模が読め、書き込みは件数に対して対数的に有界
    if (isSuppressionMilestone(suppressed)) {
      await userAuditInsert(db, serverTs, {
        event: spec.markerEvent,
        actor: {},
        // 個別行の payload は運ばない(AUDIT_SPEC §3.1: マーカーの payload は
        // 分類部・窓長・上限・抑制件数のみ)。マーカーはこの 1 件ではなく窓の
        // 状態を表すものなので、最後の個別行を代表させない
        payload: {
          ...spec.markerBasePayload,
          windowMs: LOGIN_FAILED_WINDOW_MS,
          limit: LOGIN_FAILED_WINDOW_LIMIT,
          suppressedCount: suppressed,
        },
      });
    }
    return;
  }
  await userAuditInsert(db, serverTs, event);
}

export function makeD1AuditRepo(db: Db): D1AuditRepoShape {
  return {
    appendUserEvent: (event, serverTs) =>
      Effect.promise(async () => {
        await userAuditInsert(db, serverTs, event);
      }),
    appendLoginFailed: (event, serverTs, bucket) =>
      Effect.promise(() =>
        appendWithFixedWindow(db, event, serverTs, {
          bucketKey: loginFailedBucketKey(bucket),
          markerEvent: LOGIN_FAILED_SUPPRESSED_EVENT,
          markerBasePayload: { authMethod: bucket.authMethod, reason: bucket.reason },
        }),
      ),
    appendSignupDenied: (event, serverTs, reason) =>
      Effect.promise(() =>
        appendWithFixedWindow(db, event, serverTs, {
          // バケットの名前空間はイベント名で分ける(login_failed の
          // [authMethod, reason] キーと衝突しない)
          bucketKey: JSON.stringify(["auth.signup_denied", reason]),
          markerEvent: SIGNUP_DENIED_SUPPRESSED_EVENT,
          markerBasePayload: { authMethod: "github_oauth", reason },
        }),
      ),
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
