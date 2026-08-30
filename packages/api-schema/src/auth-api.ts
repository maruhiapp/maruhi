// 認証エンドポイントの HttpApi 定義(AUTH_SPEC §3 / §4 / §5 / §6 / §11-4)。
//
// 2026-08-02 裁定 4: OAuth リダイレクト系(start / callback)も含めてすべて
// api-schema に置く(サーバー実装とクライアント導出の共有源を単一に保つ)。
// start / callback の成功応答は 302 リダイレクト(+ Set-Cookie)であり、
// ハンドラが HttpServerResponse を直接返す(success スキーマは Void)。
//
// 禁止事項(AUTH_SPEC §10): GitHub トークンはリクエスト処理中のメモリ上でのみ
// 扱われ、どのレスポンス型にも現れない。セッション / トークン生値がレスポンスに
// 現れるのは発行時の一度だけ(deviceExchange の success)。

import { OrgRoleSchema, TokenScopeSchema } from "@maruhi/core";
import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/unstable/httpapi";

import { AuthMiddleware } from "./auth-middleware.ts";
import {
  AuthFlowError,
  AuthRateLimitedError,
  ForbiddenError,
  RecoveryRateLimitedError,
  RecoveryWrapNotFoundError,
  SetupIncompleteError,
  TokenLimitError,
  TokenNotFoundError,
} from "./errors/index.ts";
import { hexString } from "./hex.ts";
import { strictPayload } from "./strict.ts";

/**
 * 302 リダイレクト(+ Set-Cookie)で完結するエンドポイントの成功宣言。
 * githubStart / githubCallback はブラウザナビゲーション専用であり、HttpApi 導出
 * クライアント(fetch は既定でリダイレクトを追従する)から呼ぶ設計ではない。
 */
const Redirect = HttpApiSchema.Empty(302);

/**
 * トークン名の上限(`deviceExchange` の payload)。
 *
 * **CLI の引数層と共有する**: ここだけに書くと、`maruhi login --token-name` の
 * 長すぎる値が device flow(ブラウザでの承認)を完走した後の encode 失敗として
 * 初めて現れる。書き方の誤りは通信より前に落とす(CLI 側の規律)ため、上限を
 * export して両側が同じ値を見る。
 */
export const MAX_TOKEN_NAME_LENGTH = 128;

/**
 * API トークンの既定 TTL(AUTH_SPEC §6 — 2026-08-30 W3a。SECURITY_REVIEW
 * 2026-08-14 L-2 の解消)。expires_at は発行時に固定する(セッション §5 の
 * スライディング更新と意図的に非対称 — トークンには定期再認証を強制する)。
 * セルフホストでの値の調整は許される(受理ポリシーであり合意規則ではない)。
 */
export const DEFAULT_TOKEN_TTL_DAYS = 90;

/**
 * 発行時に明示指定できる TTL の上限(AUTH_SPEC §6 — W3a 裁定 CF)。リース
 * 非対応の実行環境(GitLab CI / k8s / cron 等 — §14-1 の対応 issuer は v1 =
 * GitHub Actions のみ)で PAT を無人利用する場合の逃し弁で、上限つきである
 * こと自体が L-2(無期限トークン)の再導入を遮断する。CLI の引数層と共有する
 * (MAX_TOKEN_NAME_LENGTH と同じ理由 — 書き方の誤りは通信より前に落とす)。
 */
export const MAX_TOKEN_TTL_DAYS = 365;

/** 発行時の明示 TTL(日)。整数 1..MAX_TOKEN_TTL_DAYS(省略時は既定 90 日)。 */
const TokenTtlDays = Schema.Number.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(1),
  Schema.isLessThanOrEqualTo(MAX_TOKEN_TTL_DAYS),
);

/**
 * Public (unauthenticated) server configuration (AUTH_SPEC §4). The GitHub
 * OAuth client_id is public information — it appears in the authorize URL —
 * so exposing it lets a self-hosted CLI resolve it from the server URL alone.
 *
 * serverKeyFingerprintHex(AUTH_SPEC §4 — 2026-08-12)はデプロイメント keypair
 * (CRYPTO_SPEC §9)が設定済みの場合のみ載る。grant_server 実行時の照合対象。
 * serverEncPubHex は §9 の「サーバーが配布する enc 公開鍵」の配布チャネル
 * (公開鍵は公開情報。FP はその SHA-256 先頭 16 バイトで、CLI は両者の整合を
 * 再計算検証する)。
 */
export const AuthConfigSchema = Schema.Struct({
  githubClientId: Schema.String,
  serverKeyFingerprintHex: Schema.optionalKey(Schema.String),
  serverEncPubHex: Schema.optionalKey(Schema.String),
});

/**
 * Result of the device-flow exchange (AUTH_SPEC §4): the raw token, shown once.
 * `expiresAtMs` は発行時に固定された有効期限(§6 の既定 TTL — W3a)。CLI が
 * 期限を利用者へ表示するための材料で、生値と違い何度でも表示してよい。
 * optionalKey なのはバージョンスキュー耐性(PR #108 pullfrog 指摘): W3a より
 * 古いサーバーはこのフィールドを返さず、必須にすると新 CLI の `maruhi login`
 * — fail-closed な期限切れからの唯一の回復コマンド — が応答 decode で失敗し、
 * 発行済みトークンをサーバー側に孤児化させる。W3a 以降のサーバーは常に返す
 * (欠落 = 旧サーバーの検出材料。CLI は期限未申告の注意を表示する)。
 */
export const DeviceExchangeResultSchema = Schema.Struct({
  token: Schema.String,
  tokenId: Schema.String,
  userId: Schema.String,
  expiresAtMs: Schema.optionalKey(Schema.Number),
});

/**
 * One API token in the self-inventory listing (AUTH_SPEC §6 — W3a).
 * 生値・token_hash は**構造ごと存在しない**(スキーマに列がない = 実装が
 * 誤って返す経路を型で塞ぐ)。`expiresAtMs` の null は移行(裁定 CE)前の
 * 旧無期限行で、検証時には期限切れと同じ 401 で扱われる(fail-closed)。
 */
export const TokenSummarySchema = Schema.Struct({
  id: Schema.String,
  name: Schema.String,
  tokenPrefix: Schema.String,
  scopes: Schema.Array(TokenScopeSchema),
  createdAtMs: Schema.Number,
  lastUsedAtMs: Schema.NullOr(Schema.Number),
  expiresAtMs: Schema.NullOr(Schema.Number),
});

/** GET /auth/tokens: the caller's own tokens (AUTH_SPEC §6 — W3a). */
export const TokenListSchema = Schema.Struct({
  tokens: Schema.Array(TokenSummarySchema),
});

/** One org the authenticated user belongs to (AUTH_SPEC §9-1). */
export const UserOrgSchema = Schema.Struct({
  orgId: Schema.String,
  slug: Schema.String,
  name: Schema.String,
  role: OrgRoleSchema,
});

/** The authenticated user and their orgs (project creation needs an org id — §11-3). */
export const MeSchema = Schema.Struct({
  userId: Schema.String,
  orgs: Schema.Array(UserOrgSchema),
  /**
   * トークン主体のときのみ: 提示トークンのスコープ(AUTH_SPEC §6)。
   * セッション主体では欠落(スコープを持たない。呼べる面は §5 の能力制限の
   * 許可列挙に限られ、その中ではチェーン role が束縛 — W2b)。
   * クライアントが実効権限(min(スコープ, チェーン role) — §9-2)を**事前に**
   * 判定するための材料(checkpoint の監査ヘッド公証で 403 を踏まない —
   * §16-2。2026-08-28 PR-M2)。
   */
  tokenScopes: Schema.optionalKey(Schema.Array(TokenScopeSchema)),
  /**
   * トークン主体のときのみ: 提示トークンの有効期限(AUTH_SPEC §6 — W3a
   * 裁定 CI)。tokenScopes と同じ「自分が提示した資格情報の属性」であり新しい
   * 情報を開示しない。無人利用(リース非対応環境の PAT — 裁定 CF)が期限を
   * 自己観測して 401 の前に警告・再発行を仕込むための材料。一覧
   * `GET /auth/tokens`(トークン主体は `*` × admin — 裁定 CH)を開かずに
   * 自分の期限だけを知る経路でもある。
   */
  tokenExpiresAtMs: Schema.optionalKey(Schema.Number),
});

// リカバリーブロブ(AUTH_SPEC §13。CRYPTO_SPEC §8 のラップ済み master 秘密鍵)。
// サーバーから見て不透明な暗号文であり、リカバリーコード自体はワイヤに現れない。
const RecoveryNonceHex = hexString(12);
// AES-256-GCM の ct || tag: タグ込み 16 バイト以上・16 KiB 以下(§13-4 受理ポリシー)
const RecoveryCiphertextHex = Schema.String.check(
  Schema.isPattern(/^(?:[0-9a-f]{2}){16,16384}$/, {
    description: "lowercase hex AES-GCM ciphertext (16 bytes .. 16 KiB incl. tag)",
  }),
);

/** A wrapped master-secret blob on the wire (AUTH_SPEC §13-4). */
export const RecoveryWrapSchema = Schema.Struct({
  suite: Schema.Literal("maruhi/v1"),
  nonceHex: RecoveryNonceHex,
  ciphertextHex: RecoveryCiphertextHex,
});

/** GET /auth/recovery: the stored blob plus its last-update time. */
export const RecoveryWrapResultSchema = Schema.Struct({
  suite: Schema.Literal("maruhi/v1"),
  nonceHex: RecoveryNonceHex,
  ciphertextHex: RecoveryCiphertextHex,
  updatedAtMs: Schema.Number,
});

/** GET /auth/recovery/status: registration state only — never the blob (§13-2). */
export const RecoveryStatusSchema = Schema.Struct({
  registered: Schema.Boolean,
  updatedAtMs: Schema.NullOr(Schema.Number),
});

/**
 * Authentication endpoints (AUTH_SPEC §3 web OAuth, §4 device flow, §5
 * sessions, §6 tokens). Token issuance happens only through the device flow;
 * management is the presented-token self-revocation (CLI logout 用) plus the
 * W3a token-management surface: self-inventory listing and targeted revocation
 * (2026-08-28 W0 裁定で更新された §6 の線引き — 追加発行 UI / API は作らない).
 */
export const authGroup = HttpApiGroup.make("auth")
  .add(
    // 公開設定エンドポイント(AUTH_SPEC §4。セッション 11 裁定 B)。未認証。
    // 未設定サーバー(§3 の自己診断条件: client_id がプレースホルダ / 空 / 欠落、
    // または client_secret 未登録)は 503 でセットアップガイドへ誘導する
    HttpApiEndpoint.get("authConfig", "/auth/config", {
      success: AuthConfigSchema,
      error: [SetupIncompleteError],
    }),
  )
  .add(
    HttpApiEndpoint.get("githubStart", "/auth/github/start", {
      success: Redirect,
      error: [SetupIncompleteError],
    }),
  )
  .add(
    HttpApiEndpoint.get("githubCallback", "/auth/github/callback", {
      // 未認証で到達でき、リクエストごとに GitHub へのアウトバウンド(code 交換。
      // 成功時はさらに /user・/user/emails)を伴うため、クエリに明示的な上限
      // (512 文字)を課す(device/exchange と同じ論拠 — セキュリティレビュー
      // L-3 / 追補 3 A-6)。code の形式は OAuth 仕様が定めないため長さのみ検査
      // する(実 GitHub の code / state はこの上限より桁違いに短い)。
      // 長さ上限はペイロードを縛るだけで頻度は縛らないため、交換の**回数**は
      // 発信元 IP 単位の Workers Rate Limiting が有界にする(deepsec R7 —
      // device/exchange と同じ OAuth App 共有クォータを消費する経路)
      query: {
        code: Schema.String.check(Schema.isMaxLength(512)),
        state: Schema.String.check(Schema.isMaxLength(512)),
      },
      success: Redirect,
      error: [AuthFlowError, AuthRateLimitedError],
    }),
  )
  .add(
    HttpApiEndpoint.post("deviceExchange", "/auth/device/exchange", {
      // 認証前に到達できる書き込み系のため、フィールドに明示的な上限を課す
      // (D1 への肥大 JSON 蓄積の遮断。AUTH_SPEC §6)。
      // 形式事前検査(AUTH_SPEC §4 — 2026-08-15): GitHub のトークンは
      // `gh<種別 1 文字>_` プレフィックス + Base62/`_` 本体で発行される。
      // 交換はリクエストごとにサーバーから GitHub check-token API への
      // アウトバウンド呼び出しを伴い、その枠は OAuth App 単位のレート制限を
      // 受けるため、形式を満たさない入力はここで落として GitHub へ出さない。
      // これが遮断するのは無差別・形式不明の洪水まで。形式適合の洪水は
      // 発信元 IP 単位の Workers Rate Limiting(既定デプロイの wrangler.jsonc —
      // deepsec M3/B11)が best-effort で遮断し、より強い保全は引き続き運用側の
      // WAF ルールに置く(SELF_HOSTING.md — L-3)
      payload: Schema.Struct({
        githubAccessToken: Schema.String.check(
          Schema.isMaxLength(512),
          Schema.isPattern(/^gh[a-z]_[A-Za-z0-9_]+$/, {
            description: "GitHub token (gh?_ prefix + base62 body)",
          }),
        ),
        tokenName: Schema.optionalKey(
          Schema.String.check(Schema.isMaxLength(MAX_TOKEN_NAME_LENGTH)),
        ),
        scopes: Schema.optionalKey(Schema.Array(TokenScopeSchema).check(Schema.isMaxLength(100))),
        // 発行時の明示 TTL(AUTH_SPEC §6 — W3a 裁定 CF)。省略時は既定 90 日。
        // 上限(365 日)はワイヤ Schema で強制し、無期限相当の値を受けない
        expiresInDays: Schema.optionalKey(TokenTtlDays),
      }),
      success: DeviceExchangeResultSchema,
      error: [AuthFlowError, AuthRateLimitedError, SetupIncompleteError, TokenLimitError],
    }),
  )
  .add(
    HttpApiEndpoint.get("me", "/auth/me", {
      success: MeSchema,
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("logout", "/auth/logout", {
      success: HttpApiSchema.NoContent,
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("revokeToken", "/auth/token/revoke", {
      success: HttpApiSchema.NoContent,
    }).middleware(AuthMiddleware),
  )
  .add(
    // 一覧(AUTH_SPEC §6 — W3a): 本人のトークンのメタデータのみ。生値・
    // token_hash は返さない(TokenSummarySchema に列が存在しない)。
    // トークン主体は `*` × admin スコープを含む場合のみ(裁定 CH — §13-2 /
    // 本人軸監査と同水準: 窃取されたスコープ限定トークンにアカウント全域の
    // トークン目録 = 偵察材料を渡さない)。上限 100 本(§6)で有界のため
    // ページングは持たない
    HttpApiEndpoint.get("listTokens", "/auth/tokens", {
      success: TokenListSchema,
      error: [ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // 指定失効(AUTH_SPEC §6 — W3a): 認可 = セッション主体、または `*` × admin
    // スコープを含むトークンのみ。対象は本人のトークンのみ — 他人の・存在しない
    // token id は一様 404(存在秘匿 — §12-6 の削除系と同じ規律。判定順は
    // 裁定 CG: 401 → 403〔呼び出し資格のみから計算〕→ 一様 404)
    HttpApiEndpoint.delete("revokeTokenById", "/auth/tokens/:tokenId", {
      params: { tokenId: Schema.String },
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, TokenNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    // 登録・再発行 = 置換 upsert(AUTH_SPEC §13-1。旧ラップは受理と同時に消える)
    HttpApiEndpoint.put("recoveryPut", "/auth/recovery", {
      // strict 受理(§12-10 (1))。共有部品の RecoveryWrapSchema 自体には注釈せず、
      // payload ルートの使用点でのみ被せる(応答スキーマと共有されうる部品の規律)
      payload: strictPayload(RecoveryWrapSchema),
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("recoveryGet", "/auth/recovery", {
      success: RecoveryWrapResultSchema,
      error: [ForbiddenError, RecoveryWrapNotFoundError, RecoveryRateLimitedError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("recoveryStatus", "/auth/recovery/status", {
      success: RecoveryStatusSchema,
    }).middleware(AuthMiddleware),
  );
