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

/** 変数作成に同梱するステートメント(metaVersion 1 — AUTH_SPEC §12-5)。 */
export const CreateVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  ...creationLifecycleFields,
});

/** 変数 rename のステートメント(metaVersion CAS — §12-5)。 */
export const RenameVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  ...renameLifecycleFields,
});

/** 変数削除のステートメント(status deleted。name は直前 active 名 — §4.2)。 */
export const DeleteVariableMetaStatementSchema = Schema.Struct({
  ...varMetaBaseFields,
  ...deleteLifecycleFields,
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
  ...anyLifecycleFields,
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

/**
 * DEK ラップの受信者クラス(AUTH_SPEC §12-6。2026-08-12): member = チェーン上の
 * 現メンバー(user_id + enc 公開鍵で同定)、server = 有効な grant_server の
 * サーバー鍵(FP + enc 公開鍵で同定 — user_id を持たない)。省略時は member
 * (受信者クラス導入前のワイヤと同形)。
 */
export const DekRecipientClassSchema = Schema.Literals(["member", "server"]);

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
