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
// 登録署名(Ed25519、CRYPTO_SPEC §5.1)と署名者鍵フィンガープリント(§3)
const WrapSignatureHex = hexString(64);
const KeyFingerprintHex = hexString(16);

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
 */
export const EncryptedPayloadSchema = Schema.Struct({
  suite: SuiteSchema,
  aad: VariableAadSchema,
  nonceHex: NonceHex,
  ciphertextHex: ValueCiphertextHex,
});

/** An encrypted variable value on the wire. */
export type EncryptedPayload = typeof EncryptedPayloadSchema.Type;

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
