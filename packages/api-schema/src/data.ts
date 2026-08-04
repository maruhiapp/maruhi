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

import { hexString } from "./hex.ts";

/** 1 始まりの整数(epoch / version — CRYPTO_SPEC §3 / §4)。 */
const PositiveInt = Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(1));

/**
 * スイート識別子(CRYPTO_SPEC §2 設計原則 4: すべての永続データ構造が持つ)。
 * v1 の API は Literal でピン留めする(suite とエポックの結合 = v2 移行の形は
 * v2 設計まで保留 — AUTH_SPEC §12-2)。
 */
const SuiteSchema = Schema.Literal("maruhi/v1");

const NonceHex = hexString(12);
const EncPubHex = hexString(32);
const HpkeEncHex = hexString(32);
// ラップ済み DEK = 32 バイト DEK + GCM タグ 16 バイト(CRYPTO_SPEC §5)
const WrappedDekCiphertextHex = hexString(48);
// 登録署名 / 値の書き込み署名(Ed25519、CRYPTO_SPEC §5.1 / §4.1)と
// 鍵フィンガープリント(§3)
const WrapSignatureHex = hexString(64);
const ValueSignatureHex = hexString(64);
const KeyFingerprintHex = hexString(16);
// チェーンヘッド・prev の SHA-256(hex 小文字 64 文字 — CRYPTO_SPEC §4.1)
const Sha256Hex = hexString(32);
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
  writerUserId: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(1024)),
  writerKeyFingerprintHex: KeyFingerprintHex,
});

/** A distributed variable value with its writer identity. */
export type DistributedEncryptedPayload = typeof DistributedEncryptedPayloadSchema.Type;

/**
 * One HPKE-wrapped epoch DEK for one recipient (AUTH_SPEC §12-6). The
 * recipient is identified by both user id and encryption public key; the
 * server requires both to match the chain-derived member exactly.
 * `signatureHex` is the per-wrap registration signature (CRYPTO_SPEC §5.1);
 * the signer must be the calling principal, so the wire carries no signer id.
 *
 * recipientUserId の上限はチェーン合意規則の自由文字列上限(CRYPTO_SPEC §6.1 の
 * 1024 バイト)に揃える — add_member の対象はここより狭く検証されないため、
 * これより狭い上限はチェーン上の正当なメンバー宛ラップを登録不能にしうる。
 */
export const WrappedDekSchema = Schema.Struct({
  suite: SuiteSchema,
  epoch: PositiveInt,
  recipientUserId: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(1024)),
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
  signerUserId: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(1024)),
  signerKeyFingerprintHex: KeyFingerprintHex,
});

/** A wrap distributed to its recipient. */
export type RecipientDek = typeof RecipientDekSchema.Type;

/**
 * Reference naming one stored wrap — the unit of the admin-only deletion in
 * the §12-6 repair path (delete a poisoned wrap, then re-register the missing
 * one through the append path).
 */
export const DekWrapRefSchema = Schema.Struct({
  epoch: PositiveInt,
  recipientUserId: Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(1024)),
});

/** Reference naming one stored wrap (§12-6 repair path). */
export type DekWrapRef = typeof DekWrapRefSchema.Type;
