// データプレーンのワイヤ表現(AUTH_SPEC §12-2 = CRYPTO_SPEC §10 の具体化)。
//
// API 境界の不変条件(CRYPTO_SPEC §10): 変数値は EncryptedPayload としてのみ
// 表現する。平文値・DEK・秘密鍵を表す型をこのファイルに置かないこと。
//
// サーバーは AAD を暗号学的に検証できない(E2EE)。Schema が検査するのは
// トランスポート形状(hex 形式・固定長)のみで、申告 AAD と保存先座標の一致は
// ハンドラ / DO 側の受理検査、文脈束縛の強制は復号失敗(crypto のテストベクター
// が固定)が担う。

import { EnvironmentIdSchema, ProjectIdSchema, VariableIdSchema } from "@maruhi/core";
import { Schema } from "effect";

import {
  EncPubHex,
  hexString,
  HpkeEncHex,
  KeyFingerprintHex,
  ManifestSignatureHex,
  MetaSignatureHex,
  PositiveInt,
  Sha256Hex,
  ValueSignatureHex,
  WrapSignatureHex,
} from "./hex.ts";

/**
 * スイート識別子(CRYPTO_SPEC §2 設計原則 4: すべての永続データ構造が持つ)。
 * v1 の API は Literal でピン留めする(suite とエポックの結合 = v2 移行の形は
 * v2 設計まで保留 — AUTH_SPEC §12-2)。
 */
const SuiteSchema = Schema.Literal("maruhi/v1");

const NonceHex = hexString(12);
// ラップ済み DEK = 32 バイト DEK + GCM タグ 16 バイト(CRYPTO_SPEC §5)
const WrappedDekCiphertextHex = hexString(48);
// prev_value_sig_hash_hex: version 1 は空文字列、以降は 64 文字 hex(§4.1)。
// version との結合(1 ⇔ 空)は状態に依存しない検証規則としてサーバー / クライアント
// の署名検証(prev-shape-mismatch)が検査する — Schema はワイヤ形状のみ
const PrevValueSigHashHex = Schema.Union([Schema.Literal(""), Sha256Hex]);

// AES-256-GCM の ct || tag: タグ込み 16 バイト以上の hex 小文字(偶数長)
const ValueCiphertextHex = Schema.String.check(
  Schema.isPattern(/^(?:[0-9a-f]{2}){16,}$/, {
    description: "lowercase hex AES-GCM ciphertext (>= 16 bytes incl. tag)",
  }),
);

/**
 * 内部 user_id のワイヤ上限: チェーン合意規則の自由文字列上限(CRYPTO_SPEC §6.1
 * の 1024 バイト)に揃える。これより狭い上限はチェーン上の正当なメンバーを
 * 表現不能にしうる。chain.ts 側は意図的に bound しない(§6.1 — verifyChain が
 * 上限を検査する)。
 */
const BoundedUserId = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(1024));

/** Declared AAD components of a variable ciphertext (CRYPTO_SPEC §4). */
export const VariableAadSchema = Schema.Struct({
  projectId: ProjectIdSchema,
  environmentId: EnvironmentIdSchema,
  epoch: PositiveInt,
  variableId: VariableIdSchema,
  version: PositiveInt,
});

/**
 * An encrypted variable value on the wire (AUTH_SPEC §12-2): the only shape a
 * secret value ever takes across the API boundary (CRYPTO_SPEC §10).
 *
 * 2026-08-04(CRYPTO_SPEC §4.1 = セッション 12 仕様の実装 PR-2)以降、値は
 * writer の書き込み署名ブロックを伴う: prev 連鎖(prevValueSigHashHex)、
 * 認可時点のチェーンヘッド束縛(chainHeadHashHex + chainHeadSeq)、Ed25519
 * 署名(signatureHex)。push / create では writer = 呼び出し主体が契約
 * (§12-5)のため、writer の ID / FP / signed-bytes hash はワイヤに載せない。
 */
export const EncryptedPayloadSchema = Schema.Struct({
  suite: SuiteSchema,
  aad: VariableAadSchema,
  nonceHex: NonceHex,
  ciphertextHex: ValueCiphertextHex,
  prevValueSigHashHex: PrevValueSigHashHex,
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: ValueSignatureHex,
});

/** An encrypted variable value on the wire. */
export type EncryptedPayload = typeof EncryptedPayloadSchema.Type;

/**
 * A distributed (pulled) variable value (AUTH_SPEC §12-2 / §12-7): the stored
 * payload plus the verification material — the writer's user id and key
 * fingerprint at acceptance time. The receiver verifies against its own
 * verified chain history (CRYPTO_SPEC §6.3); a writer removed since then
 * stays verifiable through the chain's key history. The server-computed
 * signed-bytes hash is NOT distributed — verifiers recompute it themselves.
 */
export const DistributedEncryptedPayloadSchema = Schema.Struct({
  ...EncryptedPayloadSchema.fields,
  writerUserId: BoundedUserId,
  writerKeyFingerprintHex: KeyFingerprintHex,
});

/** A distributed variable value with its writer identity. */
export type DistributedEncryptedPayload = typeof DistributedEncryptedPayloadSchema.Type;

// ---------------------------------------------------------------------------
// メタデータステートメント(CRYPTO_SPEC §4.2 / AUTH_SPEC §12-2)。
// 名前 ↔ ID の対応と active / deleted 状態の真正性を author の Ed25519 署名が
// 束縛する。name は NFC 正規化済み(§12-1 — 実施主体は署名前のクライアント。
// サーバーは検査のみで正規化しない)。長さ上限 256 文字は §12-8 の受理ポリシー
// (値と違い専用の検証層を持たないため Schema で強制 — 旧 ResourceNameSchema)。
// ---------------------------------------------------------------------------

/** NFC 正規形かどうかは Schema でなくサーバーの 422(NameNotNfc)が検査する。 */
const StatementNameSchema = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256));

const MetaStatementStatusSchema = Schema.Literals(["active", "deleted"]);
// 変数ステートメントのレイアウト v2 は第 3 の状態 declared を持つ(CRYPTO_SPEC
// §4.2 — 宣言済み・値未設定。環境メタと v1 レイアウトは従来の 2 値のまま)
const VariableMetaStatementStatusSchema = Schema.Literals(["active", "deleted", "declared"]);
// metaVersion 1 は作成専用(status active・prev 空)なので、rename / 削除の
// リクエスト形は metaVersion >= 2 に固定される(下の narrowed struct)
const MetaVersionAtLeast2 = Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(2));
const PrevMetaSigHashHex = Schema.Union([Schema.Literal(""), Sha256Hex]);

const varMetaBaseFields = {
  suite: SuiteSchema,
  environmentId: EnvironmentIdSchema,
  variableId: VariableIdSchema,
  name: StatementNameSchema,
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: MetaSignatureHex,
};

const envMetaBaseFields = {
  suite: SuiteSchema,
  environmentId: EnvironmentIdSchema,
  name: StatementNameSchema,
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: MetaSignatureHex,
};

// ライフサイクル 3 形(作成 = metaVersion 1・active・prev 空 / rename = active /
// 削除 = deleted)。リクエストのワイヤ形を操作ごとに固定し、「作成なのに
// deleted」「削除なのに active」をサーバー検査でなく Schema(400)で拒否する
const creationLifecycleFields = {
  status: Schema.Literal("active"),
  metaVersion: Schema.Literal(1),
  prevMetaSigHashHex: Schema.Literal(""),
};
const renameLifecycleFields = {
  status: Schema.Literal("active"),
  metaVersion: MetaVersionAtLeast2,
  prevMetaSigHashHex: Sha256Hex,
};
const deleteLifecycleFields = {
  status: Schema.Literal("deleted"),
  metaVersion: MetaVersionAtLeast2,
  prevMetaSigHashHex: Sha256Hex,
};
// 配布側は全ライフサイクルを運ぶ(保存済みステートメントの自己記述形)
const anyLifecycleFields = {
  status: MetaStatementStatusSchema,
  metaVersion: PositiveInt,
  prevMetaSigHashHex: PrevMetaSigHashHex,
};

// ---------------------------------------------------------------------------
// 変数メタステートメントのレイアウト v2(CRYPTO_SPEC §4.2 / AUTH_SPEC §12-2 —
// 2026-08-30)。v1 ステートメントは従来のフィールド構成のまま(layoutVersion・
// スキーマ欄の 4 フィールドすべて不在 — strict 受理がこれを強制する)、v2 は
// layoutVersion とスキーマ欄を持つ。環境メタステートメントは対象外(v1 のまま)。
// ---------------------------------------------------------------------------

/**
 * varType の閉集合(CRYPTO_SPEC §4.2 — `""` = 未指定。検証 DSL・enum・既定値は
 * 導入しない — 裁定 CT)。閉集合の判定は Schema 検証(400 — §12-5)。
 */
export const MetaVarTypeSchema = Schema.Literals(["", "string", "number", "boolean", "url"]);

/**
 * ワイヤの layoutVersion(AUTH_SPEC §12-2): **上限を固定しない整数**。v1 は
 * フィールド不在で表す(省略 = 1)ため、明示値は 2 以上。サポート範囲(現行
 * {1, 2})の検査は Schema でなく署名検証より前の受理検査が行い、超過は
 * 「未対応レイアウト」の型付き 422 として現れる(400 の Schema エラー =
 * 改ざんと区別のつかない失敗にしない誠実な破壊様式 — CRYPTO_SPEC §4.2)。
 */
const MetaLayoutVersionSchema = Schema.Number.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(2),
);

// スキーマ欄(v2 で全フィールド必須 — required の省略時解釈をクライアント実装に
// 分散させない fail-closed。CRYPTO_SPEC §4.2)。description の上限(1024 コード
// ポイント)・文字種(制御文字拒否)は §12-8 の受理検査(422)であり Schema では
// 検査しない(表示名の 400 とは意図的に区分が違う)
const varMetaV2Fields = {
  layoutVersion: MetaLayoutVersionSchema,
  varType: MetaVarTypeSchema,
  required: Schema.Boolean,
  description: Schema.String,
};

/** 変数作成に同梱するステートメント(metaVersion 1 — AUTH_SPEC §12-5)。 */
export const CreateVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  ...creationLifecycleFields,
});

/** レイアウト v2 の値同梱作成ステートメント(status active・スキーマ欄付き)。 */
export const CreateVariableMetaStatementV2Schema = Schema.Struct({
  ...varMetaBaseFields,
  ...creationLifecycleFields,
  ...varMetaV2Fields,
});

/**
 * 宣言(declared 作成 — §12-5)のステートメント: 値なしの metaVersion 1。
 * 「値のない変数は存在しない」の唯一の例外で、レイアウト v2 限定
 * (CRYPTO_SPEC §4.2 — 裁定 CS)。作成の status は active(値同梱)または
 * declared(値なし)のみ — deleted の創出はワイヤ形が構造的に拒否する。
 */
export const DeclareVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  status: Schema.Literal("declared"),
  metaVersion: Schema.Literal(1),
  prevMetaSigHashHex: Schema.Literal(""),
  ...varMetaV2Fields,
});

/** 変数 rename のステートメント(metaVersion CAS — §12-5)。 */
export const RenameVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  ...renameLifecycleFields,
});

/**
 * レイアウト v2 の rename / スキーマ再発行ステートメント(§12-5 — 受理規則は
 * 改名と同一)。status は現在の状態を保持する(active のまま、または declared
 * のままのスキーマ再発行・rename — 状態遷移はこの形では起こせない: status が
 * 直前ステートメントと不一致なら 422 payload-mismatch。declared → active は
 * activation 複合のみ、active → declared は禁止 — CRYPTO_SPEC §4.2)。
 */
export const RenameVariableMetaStatementV2Schema = Schema.Struct({
  ...varMetaBaseFields,
  status: Schema.Literals(["active", "declared"]),
  metaVersion: MetaVersionAtLeast2,
  prevMetaSigHashHex: Sha256Hex,
  ...varMetaV2Fields,
});

/**
 * activation(declared → active — §12-5)のステートメント: 最初の値 push との
 * 複合に同梱する status active・metaVersion + 1 の v2 ステートメント。
 */
export const ActivateVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  ...renameLifecycleFields,
  ...varMetaV2Fields,
});

/** 変数削除のステートメント(status deleted。name は直前 active 名 — §4.2)。 */
export const DeleteVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  ...deleteLifecycleFields,
});

/**
 * レイアウト v2 の削除ステートメント(v2 変数の削除は必ず v2 — レイアウト
 * 単調性)。スキーマ欄・レイアウトは直前ステートメントの値をそのまま保持する
 * こと(name と同じ規約 — 不一致は 422 payload-mismatch。§12-5)。
 */
export const DeleteVariableMetaStatementV2Schema = Schema.Struct({
  ...varMetaBaseFields,
  ...deleteLifecycleFields,
  ...varMetaV2Fields,
});

/** 環境作成の複合リクエストに同梱するステートメント(§12-4)。 */
export const CreateEnvironmentMetaStatementSchema = Schema.Struct({
  ...envMetaBaseFields,
  ...creationLifecycleFields,
});

/** 環境 rename のステートメント(§12-4 → §12-5 のメタ規則)。 */
export const RenameEnvironmentMetaStatementSchema = Schema.Struct({
  ...envMetaBaseFields,
  ...renameLifecycleFields,
});

/** 環境削除のステートメント(宣言ヘッド時点 admin — §12-3)。 */
export const DeleteEnvironmentMetaStatementSchema = Schema.Struct({
  ...envMetaBaseFields,
  ...deleteLifecycleFields,
});

/**
 * A distributed variable metadata statement (AUTH_SPEC §12-2 / §12-7): the
 * stored statement plus the verification material — the author's user id and
 * key fingerprint at acceptance time. The receiver verifies against its own
 * verified chain history (CRYPTO_SPEC §6.3); an author removed since then
 * stays verifiable through the chain's key history. Name-returning responses
 * carry statements instead of bare name snapshots (§12-2) — clients must not
 * trust a name that did not pass statement verification.
 */
export const DistributedVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  // 変数側の配布は 3 状態(declared はレイアウト v2 のみ — CRYPTO_SPEC §4.2)
  status: VariableMetaStatementStatusSchema,
  metaVersion: PositiveInt,
  prevMetaSigHashHex: PrevMetaSigHashHex,
  // レイアウト v2 の運搬フィールド(§12-2): v1 ステートメントの配布には
  // **4 フィールドとも不在**(v1 の配布へ新フィールドを足さない)、v2 では
  // 4 フィールドとも存在する。存在の結合はサーバーの保存行(受理済み)が保証する
  layoutVersion: Schema.optionalKey(MetaLayoutVersionSchema),
  varType: Schema.optionalKey(MetaVarTypeSchema),
  required: Schema.optionalKey(Schema.Boolean),
  description: Schema.optionalKey(Schema.String),
  authorUserId: BoundedUserId,
  authorKeyFingerprintHex: KeyFingerprintHex,
});

/** A distributed variable metadata statement with its author identity. */
export type DistributedVariableMetaStatement = typeof DistributedVariableMetaStatementSchema.Type;

/** A distributed environment metadata statement (same shape, env kind). */
export const DistributedEnvironmentMetaStatementSchema = Schema.Struct({
  ...envMetaBaseFields,
  ...anyLifecycleFields,
  authorUserId: BoundedUserId,
  authorKeyFingerprintHex: KeyFingerprintHex,
});

/** A distributed environment metadata statement with its author identity. */
export type DistributedEnvironmentMetaStatement =
  typeof DistributedEnvironmentMetaStatementSchema.Type;

// ---------------------------------------------------------------------------
// 環境マニフェスト(CRYPTO_SPEC §4.3 / AUTH_SPEC §12-2。2026-08-18)。
// 環境のメタ状態の全体像(全変数ステートメント — tombstone 込み — のダイジェスト +
// 環境メタステートメント)を、メタ状態を変える操作の実行者が発行時点の現エポックを
// 焼き込んで署名する。メタ層の鮮度アンカー(値の §4.1 エポック整合の対応物)。
// ---------------------------------------------------------------------------

const PrevManifestSigHashHex = Schema.Union([Schema.Literal(""), Sha256Hex]);

const manifestBaseFields = {
  suite: SuiteSchema,
  environmentId: EnvironmentIdSchema,
  /** 発行時点(宣言ヘッド時点)の現エポック — メタ層の鮮度アンカー(§4.3)。 */
  epoch: PositiveInt,
  /** 全変数ステートメント(tombstone 込み)の正規ダイジェスト(§4.3)。 */
  variablesDigestHex: Sha256Hex,
  envMetaVersion: PositiveInt,
  envMetaSigHashHex: Sha256Hex,
  chainHeadHashHex: Sha256Hex,
  chainHeadSeq: PositiveInt,
  signatureHex: ManifestSignatureHex,
};

/**
 * 環境作成の複合リクエストに同梱するマニフェスト(§12-4): manifestVersion 1・
 * 変数空集合・prev 空をワイヤ形で固定する(新規環境にマニフェスト未初期化状態が
 * 構造的に存在しないことの根拠 — CRYPTO_SPEC §6.3)。
 */
export const CreateEnvironmentManifestSchema = Schema.Struct({
  ...manifestBaseFields,
  manifestVersion: Schema.Literal(1),
  prevManifestSigHashHex: Schema.Literal(""),
});

/**
 * メタ操作(変数の作成・rename・削除、環境の rename)と rotate 複合に同梱する
 * マニフェスト(§12-5 (6) の manifestVersion CAS = 申告 == 最新 + 1)。
 * manifestVersion 1 も受理する: マニフェスト導入前に作成された環境の最初の
 * メタ操作 / rotate は保存済みマニフェストなし(= 最新 0)から v1 を発行する
 * (移行手順 — session-27 §14 PR-M1)。
 */
export const EnvironmentManifestSchema = Schema.Struct({
  ...manifestBaseFields,
  manifestVersion: PositiveInt,
  prevManifestSigHashHex: PrevManifestSigHashHex,
});

/** 環境マニフェスト(発行形 — issuer は呼び出し主体が契約 §12-5 (1))。 */
export type EnvironmentManifest = typeof EnvironmentManifestSchema.Type;

/**
 * A distributed environment manifest (AUTH_SPEC §12-2 / §12-7): the stored
 * latest manifest plus the verification material — the issuer's user id and
 * key fingerprint at acceptance time. The receiver verifies against its own
 * verified chain history and the distributed statement set (CRYPTO_SPEC
 * §4.3 / §6.3 — ダイジェスト再計算・エポック整合)。**欠落 = 一律拒否**
 * (§6.3 — 「未初期化」の警告格下げ分岐は置かない)。ワイヤ上 optional なのは
 * マニフェスト導入前に作成された環境の移行完了までの過渡状態のみ(サーバーは
 * 保存行があれば必ず同梱する)。
 */
export const DistributedEnvironmentManifestSchema = Schema.Struct({
  ...manifestBaseFields,
  manifestVersion: PositiveInt,
  prevManifestSigHashHex: PrevManifestSigHashHex,
  issuerUserId: BoundedUserId,
  issuerKeyFingerprintHex: KeyFingerprintHex,
});

/** A distributed environment manifest with its issuer identity. */
export type DistributedEnvironmentManifest = typeof DistributedEnvironmentManifestSchema.Type;

// ---------------------------------------------------------------------------
// チェックポイント時点の値スナップショット列挙(AUTH_SPEC §12-7 / §14-2 —
// 2026-08-28 PR-M3)。checkpoint 受理時にサーバーが原子保存した列挙(§16-2)を
// 値付き応答へ同梱し、クライアントのチェックポイント整合・規則 2(値の非後退 —
// CRYPTO_SPEC §6.3)の材料にする。metadata-only pull は対象外(値を運ばない)。
// ---------------------------------------------------------------------------

/**
 * One entry of the checkpoint-time value snapshot (AUTH_SPEC §12-7): one
 * active variable's latest version at checkpoint acceptance and the SHA-256
 * of that version's `value_signed_bytes` (CRYPTO_SPEC §4.1 / §6.2).
 */
export const CheckpointValueSnapshotEntrySchema = Schema.Struct({
  variableId: VariableIdSchema,
  version: PositiveInt,
  valueSigHashHex: Sha256Hex,
});

/** One checkpoint-time snapshot entry (variable id / version / value-sig hash). */
export type CheckpointValueSnapshotEntry = typeof CheckpointValueSnapshotEntrySchema.Type;

/**
 * The checkpoint-time value snapshot bundled into value-bearing responses
 * (bulk pull §12-7 / lease §14-2): the enumeration the server stored at
 * checkpoint acceptance, plus the checkpoint's chain position. The position
 * is an **advisory locator only** (CRYPTO_SPEC §1 原則 6 — session-36 裁定 S):
 * the verification baseline is always the client's own chain-derived latest
 * covering checkpoint (§6.3), and the locator merely routes the §6.3-2-style
 * two-way classification (declared seq beyond the verified head = possibly
 * stale view → one bounded re-sync on the pull path; at or below it = the
 * baseline is settled, any mismatch is hard evidence).
 */
export const CheckpointValueSnapshotSchema = Schema.Struct({
  /** Chain seq of the checkpoint entry the enumeration was stored for. */
  chainSeq: PositiveInt,
  /** Entry hash of that checkpoint entry (cross-checked against the chain). */
  entryHashHex: Sha256Hex,
  values: Schema.Array(CheckpointValueSnapshotEntrySchema),
});

/** The checkpoint-time value snapshot of one environment (§12-7 / §14-2). */
export type CheckpointValueSnapshot = typeof CheckpointValueSnapshotSchema.Type;

/**
 * プロジェクトのスキーマポリシー(AUTH_SPEC §12-11 — 有効化ゲートと
 * schema-locked。既定 disabled): disabled = レイアウト v2 の新規採用を拒否 /
 * enabled = v2 受理(スキーマ欄は任意)/ locked = enabled + 変数作成に
 * layoutVersion 2 かつ varType 非空を要求。書き込み受理ポリシーであり、
 * チェーンには載せない(検証規則の入力にもしない — 配布は advisory)。
 */
export const SchemaPolicySchema = Schema.Literals(["disabled", "enabled", "locked"]);

/** The project's schema policy (AUTH_SPEC §12-11). */
export type SchemaPolicy = typeof SchemaPolicySchema.Type;

/**
 * DEK ラップの受信者クラス(AUTH_SPEC §12-6。2026-08-12): member = チェーン上の
 * 現メンバー(user_id + enc 公開鍵で同定)、server = 有効な grant_server の
 * サーバー鍵(FP + enc 公開鍵で同定 — user_id を持たない)。省略時は member
 * (受信者クラス導入前のワイヤと同形)。
 */
const DekRecipientClassSchema = Schema.Literals(["member", "server"]);

/**
 * One HPKE-wrapped epoch DEK for one recipient (AUTH_SPEC §12-6). The
 * recipient is identified by both user id and encryption public key; the
 * server requires both to match the chain-derived member exactly.
 * `signatureHex` is the per-wrap registration signature (CRYPTO_SPEC §5.1);
 * the signer must be the calling principal, so the wire carries no signer id.
 *
 * 受信者クラス server(2026-08-12)では recipientUserId 位置に**サーバー鍵 FP
 * (hex 小文字 32 文字)**を運ぶ — HPKE info / §5.1 署名対象の recipient_user_id
 * 位置と同じ置き換え(CRYPTO_SPEC §9)。同定は FP + enc 公開鍵の両方が
 * チェーン導出の有効 grant_server の payload と厳密一致すること。
 *
 * recipientUserId の上限はチェーン合意規則の自由文字列上限(CRYPTO_SPEC §6.1 の
 * 1024 バイト)に揃える — add_member の対象はここより狭く検証されないため、
 * これより狭い上限はチェーン上の正当なメンバー宛ラップを登録不能にしうる。
 */
export const WrappedDekSchema = Schema.Struct({
  suite: SuiteSchema,
  epoch: PositiveInt,
  recipientClass: Schema.optionalKey(DekRecipientClassSchema),
  recipientUserId: BoundedUserId,
  recipientEncPubHex: EncPubHex,
  encHex: HpkeEncHex,
  ciphertextHex: WrappedDekCiphertextHex,
  signatureHex: WrapSignatureHex,
});

/** One HPKE-wrapped epoch DEK for one recipient. */
export type WrappedDek = typeof WrappedDekSchema.Type;

/**
 * A wrap distributed to its recipient (the recipient is the caller — §12-6).
 * Carries the registration signature and the signer identity (user id + key
 * fingerprint at acceptance time) so the client can verify attribution
 * against the chain history (CRYPTO_SPEC §5.1).
 */
export const RecipientDekSchema = Schema.Struct({
  suite: SuiteSchema,
  epoch: PositiveInt,
  encHex: HpkeEncHex,
  ciphertextHex: WrappedDekCiphertextHex,
  signatureHex: WrapSignatureHex,
  signerUserId: BoundedUserId,
  signerKeyFingerprintHex: KeyFingerprintHex,
});

/** A wrap distributed to its recipient. */
export type RecipientDek = typeof RecipientDekSchema.Type;

/**
 * Reference naming one stored wrap — the unit of the admin-only deletion in
 * the §12-6 repair path (delete a poisoned wrap, then re-register the missing
 * one through the append path). 受信者クラス server の行は recipientUserId
 * 位置にサーバー鍵 FP を運ぶ(WrappedDekSchema と同じ規約)。
 */
export const DekWrapRefSchema = Schema.Struct({
  epoch: PositiveInt,
  recipientClass: Schema.optionalKey(DekRecipientClassSchema),
  recipientUserId: BoundedUserId,
});

/** Reference naming one stored wrap (§12-6 repair path). */
export type DekWrapRef = typeof DekWrapRefSchema.Type;

/**
 * One leased epoch DEK (CRYPTO_SPEC §9.1 / AUTH_SPEC §14-2): the server
 * opened its own server-addressed wrap and re-sealed the DEK to the
 * workload's ephemeral public key.
 *
 * Deliberately **not** a `RecipientDek`: a lease wrap is server-generated,
 * response-scoped and never persisted (§9.1), so it carries no §5.1
 * registration signature and no signer identity — those describe a wrap a
 * chain member registered, which a lease wrap never is. Keeping the two wire
 * types apart stops a lease response from being mistaken for distributable
 * wrap material.
 */
export const LeasedDekSchema = Schema.Struct({
  suite: SuiteSchema,
  epoch: PositiveInt,
  encHex: HpkeEncHex,
  ciphertextHex: WrappedDekCiphertextHex,
});

/** One leased epoch DEK, sealed to the workload's ephemeral key. */
export type LeasedDek = typeof LeasedDekSchema.Type;
