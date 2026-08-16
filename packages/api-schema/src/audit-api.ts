// 監査イベント読み取り API の HttpApi 定義(AUDIT_SPEC §6 / §7 — Phase 2 C1)。
//
// - project DO のイベント(§3.3〜3.5 + §3.4 ミラー): seq カーソルページング
//   (新しい順、limit ≤ 200)+ フィルタ(event 種別 / actor_user_id /
//   target_user_id / variable_id / environment_id — §7 の語彙のみ)。可視性
//   クラス(§6)は認可段で強制し、クラス 2 の行・フィルタは admin 未満に
//   「存在しないかのように」振る舞う(件数フィールドを返さないのも同じ理由)
// - invite.*(保存は D1 — §3.2): project_id スコープの読み取り。権限軸は
//   当該プロジェクトのチェーン role admin 以上(org admin は閲覧権限を
//   与えない — §7)
// - user 系(§3.1): 本人のみ(§6)。トークン条件は鍵素材クラス(AUTH_SPEC
//   §13-2)と同水準 — アカウント全域の履歴をスコープ限定トークンに読ませない
// - 応答は**記録どおり**の行を運ぶ(payload の名前スナップショット含む —
//   §1-3)。全フィールドがサーバー申告であり、表示名の解決はクライアントが
//   検証済みステートメント(tombstone 含む)で行う。chain.* ミラー行は
//   クライアントが検証済みチェーンと突合して検証できる(§1-5 / §6 の緩和策 —
//   payload のスナップショットも署名済みエントリ由来のため検証対象になる)
// - 追記 API は公開しない(§7 の原則 — イベントはサーバー側処理のみが生成する)

import { ProjectIdSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi";

import { AuthMiddleware } from "./auth-middleware.ts";
import { ForbiddenError, ProjectNotFoundError } from "./errors/index.ts";
import { hexString, KeyFingerprintHex, PositiveInt } from "./hex.ts";

/** ページの最大件数(AUDIT_SPEC §7: limit ≤ 200。超過は Schema の 400)。 */
export const MAX_AUDIT_EVENTS_PAGE_LIMIT = 200;

/** limit 省略時の既定件数(サーバー側で適用)。 */
export const DEFAULT_AUDIT_EVENTS_PAGE_LIMIT = 50;

/** 行識別子・カーソルの形式(16 バイト hex — §5.1 row_id)。 */
const RowIdHex = hexString(16);

/** The recorded actor of an audit event (AUDIT_SPEC §2). */
export const AuditActorSchema = Schema.Struct({
  type: Schema.Literals(["user", "server", "system"]),
  userId: Schema.optionalKey(Schema.String),
  keyFingerprintHex: Schema.optionalKey(KeyFingerprintHex),
  apiTokenId: Schema.optionalKey(Schema.String),
});

/**
 * One recorded audit event (AUDIT_SPEC §5.1 columns). Shared by every audit
 * read endpoint (project DO events, invite.* rows, user-scoped rows) so the
 * consumers — `maruhi audit` and the Phase 2 web audit UI — handle a single
 * wire shape; fields a given store never records are simply absent.
 *
 * 識別子フィールド(environmentId 等)は素の文字列: 書き込み時の Schema が
 * 形式を強制済みで、読み取り側で形式を再表明すると歴史行(受理ポリシー改訂前の
 * 行)の配布が encode 失敗で 500 になる(監査の忠実返却を壊す)。
 */
export const AuditEventSchema = Schema.Struct({
  /**
   * ワイヤ行識別子 = 16 バイト乱数(AUDIT_SPEC §5.1 row_id)。ページング
   * カーソル(before)にもこれを使う。採番 seq と独立で序数距離を運ばない
   * (§7 — 件数非漏洩)。
   */
  id: RowIdHex,
  /**
   * 保存採番(§5.1 — 無欠番)。**admin 可視(チェーン role admin ×
   * トークンスコープ admin)の project DO 応答にのみ**載る(§6 の
   * 「欠番 = 削除の痕跡」検知の材料)。D1 経路(invites / self)は常に欠落
   * (デプロイメント全域の autoincrement 序数を漏らさない — §7)。
   */
  seq: Schema.optionalKey(PositiveInt),
  serverTs: Schema.Number,
  clientTs: Schema.optionalKey(Schema.Number),
  event: Schema.String,
  actor: AuditActorSchema,
  targetUserId: Schema.optionalKey(Schema.String),
  targetKeyFingerprintHex: Schema.optionalKey(KeyFingerprintHex),
  environmentId: Schema.optionalKey(Schema.String),
  variableId: Schema.optionalKey(Schema.String),
  epoch: Schema.optionalKey(PositiveInt),
  version: Schema.optionalKey(PositiveInt),
  chainSeq: Schema.optionalKey(PositiveInt),
  orgId: Schema.optionalKey(Schema.String),
  projectId: Schema.optionalKey(Schema.String),
  /** 記録どおりの補足 JSON(サーバー申告 — 冒頭コメントの検証規律を参照)。 */
  payload: Schema.optionalKey(Schema.Record(Schema.String, Schema.Json)),
});

/** 監査読み取りの成功応答(全エンドポイント共通)。件数フィールドは返さない。 */
export const AuditEventsPageSchema = Schema.Struct({
  events: Schema.Array(AuditEventSchema),
});

// クエリ文字列の limit。QueryConstraint(string への encode)を満たすため
// NumberFromString ベースで定義する
const PageLimitFromString = Schema.NumberFromString.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
  Schema.isLessThanOrEqualTo(MAX_AUDIT_EVENTS_PAGE_LIMIT),
);

// フィルタ値の受理上限。user_id はチェーン合意規則の自由文字列上限
// (CRYPTO_SPEC §6.1 の 1024 バイト)、イベント名・変数/環境 ID は §12-1 /
// §3 の語彙で十分に短い
const EventNameFilter = Schema.String.check(Schema.isMaxLength(64));
const UserIdFilter = Schema.String.check(Schema.isMaxLength(1024));
const IdFilter = Schema.String.check(Schema.isMaxLength(64));

/**
 * カーソルページングのクエリ(全エンドポイント共通)。before は前ページ
 * 末尾行の `id`(不透明な row_id)で、その行より古い行から返す。閲覧者に
 * 不可視・不明な id は「空ページ」として振る舞う(存在オラクルにしない — §7)。
 */
const pageQuery = {
  before: Schema.optionalKey(RowIdHex),
  limit: Schema.optionalKey(PageLimitFromString),
};

export const auditGroup = HttpApiGroup.make("audit")
  .add(
    HttpApiEndpoint.get("events", "/projects/:projectId/audit/events", {
      params: { projectId: ProjectIdSchema },
      query: {
        ...pageQuery,
        event: Schema.optionalKey(EventNameFilter),
        // admin 未満は本人指定のみ可(他人指定は 403 — §6 の「他人が actor の
        // 行の横断検索はクラス 2」。データ非依存の静的規則なので存在情報は
        // 漏れない)
        actorUserId: Schema.optionalKey(UserIdFilter),
        targetUserId: Schema.optionalKey(UserIdFilter),
        variableId: Schema.optionalKey(IdFilter),
        environmentId: Schema.optionalKey(IdFilter),
      },
      success: AuditEventsPageSchema,
      error: [ProjectNotFoundError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // invite.* の読み取り(§7 の例外規定): D1 保存だが権限軸はプロジェクトの
    // チェーン role admin 以上 × トークンスコープ admin(§6 クラス 2 と同一)
    HttpApiEndpoint.get("invites", "/projects/:projectId/audit/invites", {
      params: { projectId: ProjectIdSchema },
      query: pageQuery,
      success: AuditEventsPageSchema,
      error: [ProjectNotFoundError, ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // user 系(§3.1)の本人閲覧(§6)。セッション主体、または `*` × admin
    // スコープのトークンのみ(AUTH_SPEC §13-2 と同水準 — 要監視イベントを
    // 含むアカウント全域の履歴を、露出しやすいスコープ限定トークンに読ませない)
    HttpApiEndpoint.get("self", "/auth/audit/events", {
      query: pageQuery,
      success: AuditEventsPageSchema,
      error: [ForbiddenError],
    }).middleware(AuthMiddleware),
  );
