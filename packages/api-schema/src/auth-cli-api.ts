// CLI ログイン(サーバー仲介 web-flow ハンドオフ)の HttpApi 定義
// (AUTH_SPEC §4 — 2026-08-31 全面改訂。旧 GitHub Device Flow を置換)。
//
// 原則(§4): CLI はアイデンティティプロバイダを知らない。本グループのワイヤに
// プロバイダ固有フィールドを置かず、verificationUrl は CLI にとって不透明な
// URL とする。flowToken は CLI 専用の bearer 資格情報であり、ブラウザチャネル
// (URL・ページ・リダイレクト)には決して載せない(§4-1 (1))。
//
// ブラウザ脚(cliVerify / cliApprove)はブラウザナビゲーション / フォーム POST
// 専用で、ハンドラが HTML(スクリプトなし — §4-1 (4))を HttpServerResponse で
// 直接返す。失敗の出し分けは §4-2 の一様拒否規律に従い、型付きエラーを宣言
// しない(フロー状態のオラクルを作らない)。
//
// 本グループのいかなる操作もセッション能力の許可列挙(session-capability.ts の
// SESSION_ALLOWED_ENDPOINTS)に追加しない — 承認の資格はチケットであって
// セッションではない(§4-1 (3)。全 4 面は未認証面として分類する)。

import { TokenScopeSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/unstable/httpapi";

import { TokenNameSchema, TokenTtlDays } from "./auth-api.ts";
import {
  AuthRateLimitedError,
  CliFlowExpiredError,
  CliFlowRejectedError,
  SetupIncompleteError,
  TokenLimitError,
} from "./errors/index.ts";
import { hexString } from "./hex.ts";

/**
 * ポーリング間隔の下限(秒 — AUTH_SPEC §4-1 (5))。サーバーは応答の
 * `pollIntervalSeconds` にこの値を載せ、CLI は応答値をこの下限で clamp する
 * (敵対的・誤設定サーバーの 0 / 負値でビジースピンしない)。超過ポーリングは
 * サーバーが 429 で拒否してよい。
 */
export const MIN_CLI_POLL_INTERVAL_SECONDS = 5;

/** 公開相関子 flowId(128-bit 乱数 hex — §4-1 (1) の推測不能性要件)。 */
export const CliFlowIdSchema = hexString(16);

/**
 * CLI 専用の bearer 資格情報(自己完結の署名形式 — §4-1 (1))。CLI にとって
 * 不透明で、形式はサーバー実装の詳細。未認証の書き込み面なのでサイズ上限のみ
 * ワイヤで縛る。
 */
const CliFlowTokenSchema = Schema.String.check(Schema.isMaxLength(512));

/**
 * `POST /auth/cli/start` の応答(AUTH_SPEC §4-1 (1))。サーバーはこの時点で
 * 何も保存しない(無記録 — 裁定 DH)。verificationUrl は vsig(ドメイン分離
 * された MAC)で覆われ、URL の知識はポーリング資格を一切与えない。
 */
export const CliStartResultSchema = Schema.Struct({
  flowId: CliFlowIdSchema,
  flowToken: Schema.String,
  userCode: Schema.String,
  verificationUrl: Schema.String,
  expiresInSeconds: Schema.Number,
  pollIntervalSeconds: Schema.Number,
});

/** poll: ブラウザ脚が未到達(行なし = 無記録 start の正常系)または承認待ち。 */
export const CliPollPendingSchema = Schema.Struct({
  status: Schema.Literal("pending"),
});

/**
 * poll: 承認済みフローの単回発行結果(AUTH_SPEC §4-1 (5) — 旧 device 交換と
 * 同じ応答形)。生値 `token` はこの応答の一度だけワイヤに現れる(§6 / §10)。
 * `expiresAtMs` は発行時に固定された有効期限(§6 の既定 TTL)。
 */
export const CliPollApprovedSchema = Schema.Struct({
  status: Schema.Literal("approved"),
  token: Schema.String,
  tokenId: Schema.String,
  userId: Schema.String,
  expiresAtMs: Schema.Number,
});

/** poll: 承認ページで明示的に拒否された(§4-1 (4) の拒否操作)。 */
export const CliPollDeniedSchema = Schema.Struct({
  status: Schema.Literal("denied"),
});

/**
 * `POST /auth/cli/poll` の応答(§4-1 (5))。pending / denied は正当な flowToken
 * 保持者(= フロー作成者自身)に返す型付き状態で、新しい情報を運ばない
 * (§4-2)。expired は型付きエラー(CliFlowExpired)、資格不一致は一様拒否
 * (CliFlowRejected)。
 */
export const CliPollResultSchema = Schema.Union([
  CliPollApprovedSchema,
  CliPollPendingSchema,
  CliPollDeniedSchema,
]);

/**
 * ブラウザ脚 `GET /auth/cli/verify` のクエリ(§4-1 (3))。verificationUrl が
 * 運ぶ vsig 済みパラメータ一式。すべて optionalKey で宣言し、欠落・改竄の検査は
 * ハンドラが行って一様な**エラーページ**(HTML)で拒否する — スキーマ境界の
 * JSON 400 をブラウザに見せない。上限は未認証面のサイズ規律のみ
 * (githubCallback のクエリ上限と同じ論拠)。
 */
const cliVerifyQuery = {
  flow: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(64))),
  exp: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(32))),
  code: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(64))),
  name: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(512))),
  scopes: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(16384))),
  days: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(8))),
  vsig: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(128))),
};

/**
 * 承認フォーム `POST /auth/cli/approve` の受理形(§4-1 (4))。スクリプトなし
 * 承認ページからの素のフォーム POST(application/x-www-form-urlencoded)。
 * 資格はページに埋め込まれた単回・短命の承認チケットであり、セッションでは
 * ない。欠落・不一致の検査はハンドラが行い一様なエラーページで拒否する。
 */
const CliApproveFormSchema = Schema.Struct({
  flowId: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(64))),
  ticket: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(128))),
  decision: Schema.optionalKey(Schema.String.check(Schema.isMaxLength(16))),
}).pipe(HttpApiSchema.asFormUrlEncoded());

/** ブラウザナビゲーション用の 302(auth-api.ts の Redirect と同じ宣言)。 */
const Redirect = HttpApiSchema.Empty(302);

/** ハンドラが HttpServerResponse(HTML)を直接返す面の成功宣言。 */
const HtmlPage = Schema.String.pipe(HttpApiSchema.asText({ contentType: "text/html" }));

/**
 * CLI ログインエンドポイント(AUTH_SPEC §4)。全面が未認証
 * (session-capability.ts の UNAUTHENTICATED_ENDPOINTS に分類):
 *
 * - `cliStart`: 無記録 start(フロー資格の発行のみ — 裁定 DH)
 * - `cliVerify`: vsig の無状態検証 → §3 の web OAuth へリダイレクト
 * - `cliApprove`: 承認ページのフォーム POST(資格 = 単回承認チケット)
 * - `cliPoll`: flowToken の無状態検証 → 行引き → 単回発行(CAS ゲート)
 */
export const authCliGroup = HttpApiGroup.make("authCli")
  .add(
    HttpApiEndpoint.post("cliStart", "/auth/cli/start", {
      // 発行パラメータの意味論は §6(旧 device 交換と同一)。未認証面なので
      // サイズ上限をワイヤで縛る(スコープ 100 エントリ・TTL 1..365)
      payload: Schema.Struct({
        tokenName: Schema.optionalKey(TokenNameSchema),
        scopes: Schema.optionalKey(Schema.Array(TokenScopeSchema).check(Schema.isMaxLength(100))),
        expiresInDays: Schema.optionalKey(TokenTtlDays),
      }),
      success: CliStartResultSchema,
      error: [SetupIncompleteError, AuthRateLimitedError],
    }),
  )
  .add(
    HttpApiEndpoint.get("cliVerify", "/auth/cli/verify", {
      query: cliVerifyQuery,
      success: Redirect,
    }),
  )
  .add(
    HttpApiEndpoint.post("cliApprove", "/auth/cli/approve", {
      payload: CliApproveFormSchema,
      success: HtmlPage,
    }),
  )
  .add(
    HttpApiEndpoint.post("cliPoll", "/auth/cli/poll", {
      payload: Schema.Struct({
        flowId: CliFlowIdSchema,
        flowToken: CliFlowTokenSchema,
      }),
      success: CliPollResultSchema,
      error: [CliFlowExpiredError, CliFlowRejectedError, AuthRateLimitedError, TokenLimitError],
    }),
  );
