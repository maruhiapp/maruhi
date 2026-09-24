// master 鍵ラップ台帳 API の HttpApi 定義(AUTH_SPEC §13-6〜13-10 — KL3。
// CRYPTO_SPEC §8 のクラス S〔passkey-prf〕/ G〔保護者〕/ H〔ハンドオフ〕の
// サーバー保存・配布面)。recovery-code 経路(§13-1〜13-5)は auth-api.ts のまま。
//
// - すべてのラップ・分片はサーバーから見て不透明な暗号文。KEK の素材(PRF 出力・
//   分片の平文・一時秘密鍵)はどの型にも現れない
// - 認可(§13-7): `status` は認証済み主体すべて(セッション可 — §5 の許可列挙)。
//   それ以外は `*` × admin トークンのみ(§13-2 の鍵素材条件。セッション主体は拒否)
// - ハンドオフの一時公開鍵 E.pub はワイヤに載らない(CRYPTO_SPEC §8.4 — コードは
//   人が運ぶ)。サーバーが知るのは request_id(E.pub からの導出値)だけ

import { Schema } from "effect";
import { HttpApiEndpoint, HttpApiGroup, HttpApiSchema } from "effect/unstable/httpapi";

import { RecoveryWrapSchema, TOKEN_NAME_FORBIDDEN_CLASS } from "./auth-api.ts";
import { AuthMiddleware } from "./auth-middleware.ts";
import {
  ForbiddenError,
  HandoffConflictError,
  HandoffNotFoundError,
  KeyWrapNotFoundError,
  KeyWrapPolicyError,
  KeyWrapRateLimitedError,
} from "./errors/index.ts";
import { EncPubHex, hexString, HpkeEncHex, KeyFingerprintHex, Sha256Hex } from "./hex.ts";
import { strictPayload } from "./strict.ts";

/** 保護者グループの閾値モード(CRYPTO_SPEC §8.3): any = 1-of-n / all = n-of-n。 */
export const GuardianModeSchema = Schema.Literals(["any", "all"]);

/** 台帳の受理ポリシー(AUTH_SPEC §13-8 — 合意規則ではない)。 */
export const MAX_PASSKEY_WRAPS_PER_USER = 5;
export const MAX_GUARDIAN_GROUPS_PER_USER = 5;
export const MAX_GUARDIAN_SHARES_PER_GROUP = 5;
/**
 * 分片の端末行の上限 / グループ(AUTH_SPEC §13-6 — 2026-09-19 DK): 論理分片(保護者)
 * 5 × 保護者 1 人の有効端末 16(§12-8)。同じ share_index が保護者の端末数ぶん並ぶ。
 */
export const MAX_GUARDIAN_DEVICES_PER_GUARDIAN = 16;
export const MAX_GUARDIAN_SHARE_ROWS_PER_GROUP =
  MAX_GUARDIAN_SHARES_PER_GROUP * MAX_GUARDIAN_DEVICES_PER_GUARDIAN;
/**
 * 1 要求あたりの承認数上限 = 構造的な天井そのもの(グループ数 × 分片上限 —
 * AUTH_SPEC §13-8。旧端末経路の 1 行は 2026-09-19 DK K4 で削除)。承認行の PK
 * `(request_id, source, share_index)` と役割検査(分片は自分の (group, index) のみ)が
 * この値を超える行を作らせないため、上限検査は受理ポリシーの宣言であり、実効の
 * 境界は構造が担う(PR #168 レビュー指摘 — 導出値にして両者を一致させた)。
 */
export const MAX_HANDOFF_APPROVALS_PER_REQUEST =
  MAX_GUARDIAN_GROUPS_PER_USER * MAX_GUARDIAN_SHARES_PER_GROUP;
/** ハンドオフ要求の有効期間(§13-8: 15 分)。 */
export const HANDOFF_REQUEST_TTL_MS = 15 * 60 * 1000;

/** ULID 形の識別子(wrap_id / group_id)。 */
const LedgerIdSchema = Schema.String.check(
  Schema.isPattern(/^[0-9A-HJKMNP-TV-Z]{26}$/, { description: "ULID" }),
);

/** WebAuthn credential id(可変長。1..1024 バイト hex)。 */
const CredentialIdHex = Schema.String.check(
  Schema.isPattern(/^(?:[0-9a-f]{2}){1,1024}$/, {
    description: "lowercase hex credential id (1 .. 1024 bytes)",
  }),
);

/** HPKE 単発 Seal の 32 バイト平文(分片 / KEK_h)の暗号文 = 32 + 16 タグ。 */
const ShareCiphertextHex = hexString(48);

/** 分片番号(1..n)/ ハンドオフの share_index。 */
const ShareIndexSchema = Schema.Int.check(
  Schema.isBetween({ minimum: 1, maximum: MAX_GUARDIAN_SHARES_PER_GROUP }),
);

/**
 * passkey の表示用ラベル(§13-9 — 制御文字・双方向制御文字を含まない。
 * トークン名と同じ受理規律。64 文字以下)。
 */
/**
 * passkey ラベルの受理形(CLI の宣言側も同じ正規表現で事前検査する)。
 * 禁止クラスは TOKEN_NAME_FORBIDDEN_CLASS と共有し、§13-9 の「トークン名と
 * 同じ受理規律」を漂移させない。
 */
export const PASSKEY_LABEL_PATTERN = new RegExp(`^[^${TOKEN_NAME_FORBIDDEN_CLASS}]{1,64}$`, "u");

export const PasskeyLabelSchema = Schema.String.check(
  Schema.isPattern(PASSKEY_LABEL_PATTERN, {
    description: "passkey label (1 .. 64 chars, no control / bidi characters)",
  }),
);

/**
 * 登録(POST)の payload(§13-9 PasskeyWrapRegistration)。`wrapId` はクライアントが
 * 採番する(ULID): ラップの AAD が wrap_id を束縛する(CRYPTO_SPEC §8.1)ため、
 * サーバー採番では暗号化の前に id が決まらない。衝突は 422 `duplicate-id`。
 */
export const PasskeyWrapRegistrationSchema = Schema.Struct({
  wrapId: LedgerIdSchema,
  wrap: RecoveryWrapSchema,
  credentialIdHex: CredentialIdHex,
  /** 登録ごとの乱数 PRF salt(CRYPTO_SPEC §8.2 — 公開パラメータ) */
  prfSaltHex: hexString(32),
  rpId: Schema.Literal("localhost"),
  label: Schema.optionalKey(PasskeyLabelSchema),
});

/** passkey ラップの配布形(§13-9 PasskeyWrapResult)。 */
export const PasskeyWrapResultSchema = Schema.Struct({
  wrapId: LedgerIdSchema,
  wrap: RecoveryWrapSchema,
  credentialIdHex: CredentialIdHex,
  prfSaltHex: hexString(32),
  rpId: Schema.Literal("localhost"),
  label: Schema.NullOr(PasskeyLabelSchema),
  updatedAtMs: Schema.Number,
});

/**
 * 保護者の端末 1 つ分の分片(§13-9 GuardianShare — 2026-09-19 DK: 同じ論理分片
 * share_index を保護者の各有効端末鍵へ封印するため、同じ shareIndex が端末数ぶん並ぶ)。
 */
export const GuardianShareSchema = Schema.Struct({
  shareIndex: Schema.Int.check(
    Schema.isBetween({ minimum: 1, maximum: MAX_GUARDIAN_SHARES_PER_GROUP }),
  ),
  guardianUserId: Schema.String,
  guardianEncPubHex: EncPubHex,
  guardianKeyFingerprintHex: KeyFingerprintHex,
  encHex: HpkeEncHex,
  ciphertextHex: ShareCiphertextHex,
});

/**
 * グループ作成(POST)の payload(§13-9 GuardianGroupRegistration)。`groupId` は
 * クライアント採番(ULID — AAD / 分片 info が group_id を束縛するため。passkey と同じ)。
 */
export const GuardianGroupRegistrationSchema = Schema.Struct({
  groupId: LedgerIdSchema,
  mode: GuardianModeSchema,
  wrap: RecoveryWrapSchema,
  shares: Schema.Array(GuardianShareSchema).check(
    Schema.isMinLength(1),
    Schema.isMaxLength(MAX_GUARDIAN_SHARE_ROWS_PER_GROUP),
  ),
});

/** グループのブロブ配布形(§13-9 GuardianGroupResult)。分片は運ばない。 */
export const GuardianGroupResultSchema = Schema.Struct({
  groupId: LedgerIdSchema,
  mode: GuardianModeSchema,
  wrap: RecoveryWrapSchema,
  createdAtMs: Schema.Number,
});

/** 台帳の状態(`GET /auth/key-wraps` — ラップ・分片・秘密のパラメータを運ばない)。 */
export const KeyWrapStatusSchema = Schema.Struct({
  recoveryCode: Schema.Struct({
    registered: Schema.Boolean,
    updatedAtMs: Schema.NullOr(Schema.Number),
  }),
  passkeys: Schema.Array(
    Schema.Struct({
      wrapId: LedgerIdSchema,
      label: Schema.NullOr(PasskeyLabelSchema),
      credentialIdHex: CredentialIdHex,
      /**
       * 登録ごとの prf_salt(CRYPTO_SPEC §8.2 の公開パラメータ — §13-7 2026-09-13 改訂)。
       * 復元クライアントが PRF 儀式の前に要する(integration-options.md 補足 20-6 ②′)。
       */
      prfSaltHex: hexString(32),
      updatedAtMs: Schema.Number,
    }),
  ),
  guardianGroups: Schema.Array(
    Schema.Struct({
      groupId: LedgerIdSchema,
      mode: GuardianModeSchema,
      createdAtMs: Schema.Number,
      guardians: Schema.Array(
        Schema.Struct({
          shareIndex: Schema.Int,
          guardianUserId: Schema.String,
          guardianKeyFingerprintHex: KeyFingerprintHex,
        }),
      ),
    }),
  ),
});

/** 自分が保護者である ward の一覧の 1 行(§13-7 `GET /auth/guardian/wards`)。 */
export const WardSummarySchema = Schema.Struct({
  wardUserId: Schema.String,
  /** linked_identities.provider_login の表示用スナップショット(識別子ではない — §2) */
  wardLogin: Schema.NullOr(Schema.String),
  groupId: LedgerIdSchema,
  mode: GuardianModeSchema,
  shareIndex: Schema.Int,
  createdAtMs: Schema.Number,
});

/** 自分の端末 1 つ宛の分片行(`deviceShares` の要素 — 2026-09-19 DK K3)。 */
export const GuardianDeviceShareSchema = Schema.Struct({
  guardianKeyFingerprintHex: KeyFingerprintHex,
  guardianEncPubHex: EncPubHex,
  encHex: HpkeEncHex,
  ciphertextHex: ShareCiphertextHex,
});

/**
 * 自分宛の分片(§13-7 `GET /auth/guardian/shares/:groupId`)。端末軸(2026-09-19 DK
 * K3 — 設計録 dk-design.md §8 K3-10): 従来のフィールドは自分の端末行のうち FP 昇順の
 * 先頭行(端末 1 つなら唯一の行 = 従来どおり)、`deviceShares` は自分の**全端末行**。
 * K4 以降のクライアントは `deviceShares` から手元の端末鍵 FP の行を選ぶ。任意なのは
 * 本追補以前のサーバーが載せないため。
 */
export const GuardianShareResultSchema = Schema.Struct({
  groupId: LedgerIdSchema,
  wardUserId: Schema.String,
  mode: GuardianModeSchema,
  shareIndex: Schema.Int,
  encHex: HpkeEncHex,
  ciphertextHex: ShareCiphertextHex,
  deviceShares: Schema.optionalKey(Schema.Array(GuardianDeviceShareSchema)),
});

/** ハンドオフの request_id(CRYPTO_SPEC §8.4 — SHA-256 hex)。 */
export const HandoffRequestIdSchema = Sha256Hex;

/**
 * 承認の source = 保護者グループの id(§13-9)。旧端末経路の `"device"` は 2026-09-19 DK
 * (K4)で削除した — Schema がワイヤで拒む(400。AUTH_SPEC §13-7)。
 */
export const HandoffSourceSchema = LedgerIdSchema;

/** 要求の照会(承認者向け — §13-7)。`roles` は呼び出し主体が取れる承認の形。 */
export const HandoffLookupSchema = Schema.Struct({
  wardUserId: Schema.String,
  wardLogin: Schema.NullOr(Schema.String),
  expiresAtMs: Schema.Number,
  roles: Schema.Array(
    Schema.Struct({ groupId: LedgerIdSchema, mode: GuardianModeSchema, shareIndex: Schema.Int }),
  ),
});

/** 承認(POST)の payload(§13-9 HandoffApproval — blob 列は無い。2026-09-19 DK)。 */
export const HandoffApprovalSchema = Schema.Struct({
  source: HandoffSourceSchema,
  shareIndex: ShareIndexSchema,
  /** 承認者の端末鍵 FP(自己申告。ward クライアントがチェーン導出の FP と突合する) */
  approverKeyFingerprintHex: KeyFingerprintHex,
  encHex: HpkeEncHex,
  ciphertextHex: ShareCiphertextHex,
});

/** 承認の配布形(§13-9 HandoffApprovalResult)。 */
export const HandoffApprovalResultSchema = Schema.Struct({
  source: HandoffSourceSchema,
  shareIndex: ShareIndexSchema,
  approverUserId: Schema.String,
  approverKeyFingerprintHex: KeyFingerprintHex,
  encHex: HpkeEncHex,
  ciphertextHex: ShareCiphertextHex,
  createdAtMs: Schema.Number,
});

/** passkey ラップの登録(`POST /auth/key-wraps/passkey`)の応答: 採番されたラップ id。 */
export const PasskeyWrapRegisterResultSchema = Schema.Struct({ wrapId: LedgerIdSchema });

/** 保護者グループの作成(`POST /auth/key-wraps/guardians`)の応答: 採番されたグループ id。 */
export const GuardianGroupCreateResultSchema = Schema.Struct({ groupId: LedgerIdSchema });

/** 自分が保護者である ward の一覧(`GET /auth/guardian/wards`)の応答 envelope。 */
export const WardListSchema = Schema.Struct({ wards: Schema.Array(WardSummarySchema) });

/**
 * ハンドオフ要求の作成(`POST /auth/handoff`)の応答: 要求の期限(`HANDOFF_REQUEST_TTL_MS`
 * 後)。端末追加要求の `DeviceAddRequestCreateResultSchema` とは期限の意味が違うので
 * 共有しない(DK K9-4)。
 */
export const HandoffCreateResultSchema = Schema.Struct({ expiresAtMs: Schema.Number });

/** ハンドオフ要求への承認の一覧(`GET /auth/handoff/:requestId/approvals`)の応答 envelope。 */
export const HandoffApprovalListSchema = Schema.Struct({
  approvals: Schema.Array(HandoffApprovalResultSchema),
});

/**
 * Master-key wrap ledger endpoints (AUTH_SPEC §13-7). All are token-only
 * (`*` × admin — §13-2) except `status`, which any authenticated principal
 * (session included) may read.
 */
export const keyWrapsGroup = HttpApiGroup.make("keyWraps")
  .add(
    HttpApiEndpoint.get("status", "/auth/key-wraps", {
      success: KeyWrapStatusSchema,
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("passkeyRegister", "/auth/key-wraps/passkey", {
      // strict 受理(§12-10 (1) — ラップ = 鍵素材の登録)
      payload: strictPayload(PasskeyWrapRegistrationSchema),
      success: PasskeyWrapRegisterResultSchema,
      error: [ForbiddenError, KeyWrapPolicyError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("passkeyGet", "/auth/key-wraps/passkey/:wrapId", {
      params: { wrapId: LedgerIdSchema },
      success: PasskeyWrapResultSchema,
      error: [ForbiddenError, KeyWrapNotFoundError, KeyWrapRateLimitedError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete("passkeyDelete", "/auth/key-wraps/passkey/:wrapId", {
      params: { wrapId: LedgerIdSchema },
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, KeyWrapNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("guardianCreate", "/auth/key-wraps/guardians", {
      payload: strictPayload(GuardianGroupRegistrationSchema),
      success: GuardianGroupCreateResultSchema,
      error: [ForbiddenError, KeyWrapPolicyError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("guardianGet", "/auth/key-wraps/guardians/:groupId", {
      params: { groupId: LedgerIdSchema },
      success: GuardianGroupResultSchema,
      error: [ForbiddenError, KeyWrapNotFoundError, KeyWrapRateLimitedError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete("guardianDelete", "/auth/key-wraps/guardians/:groupId", {
      params: { groupId: LedgerIdSchema },
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, KeyWrapNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("wards", "/auth/guardian/wards", {
      success: WardListSchema,
      error: [ForbiddenError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("myShare", "/auth/guardian/shares/:groupId", {
      params: { groupId: LedgerIdSchema },
      success: GuardianShareResultSchema,
      error: [ForbiddenError, KeyWrapNotFoundError, KeyWrapRateLimitedError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("handoffCreate", "/auth/handoff", {
      // 運ぶのは request_id(E.pub の導出値)だけ — 署名済み構造・暗号文・鍵素材を
      // 含まないため strict 対象外(STRICT_EXEMPT_PAYLOAD_ENDPOINTS)
      payload: Schema.Struct({ requestId: HandoffRequestIdSchema }),
      success: HandoffCreateResultSchema,
      error: [ForbiddenError, HandoffConflictError, KeyWrapRateLimitedError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("handoffLookup", "/auth/handoff/:requestId", {
      params: { requestId: HandoffRequestIdSchema },
      success: HandoffLookupSchema,
      error: [ForbiddenError, HandoffNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.post("handoffApprove", "/auth/handoff/:requestId/approvals", {
      params: { requestId: HandoffRequestIdSchema },
      // strict 受理(§12-10 (1) — 再封印した分片 / KEK_h = 鍵素材の暗号文)
      payload: strictPayload(HandoffApprovalSchema),
      success: HttpApiSchema.NoContent,
      error: [
        ForbiddenError,
        HandoffNotFoundError,
        HandoffConflictError,
        KeyWrapPolicyError,
        KeyWrapRateLimitedError,
      ],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.get("handoffApprovals", "/auth/handoff/:requestId/approvals", {
      params: { requestId: HandoffRequestIdSchema },
      success: HandoffApprovalListSchema,
      error: [ForbiddenError, HandoffNotFoundError],
    }).middleware(AuthMiddleware),
  )
  .add(
    HttpApiEndpoint.delete("handoffCancel", "/auth/handoff/:requestId", {
      params: { requestId: HandoffRequestIdSchema },
      success: HttpApiSchema.NoContent,
      error: [ForbiddenError, HandoffNotFoundError],
    }).middleware(AuthMiddleware),
  );
