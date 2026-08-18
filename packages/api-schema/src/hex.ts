// 固定長 hex 小文字文字列の Schema ヘルパと、ドメイン別名の一元定義
// (チェーン・データプレーン・認証で共用)。
//
// 命名の規約: 「意味も幅も同じ」ものは 1 名に統合し(SHA-256 ハッシュ =
// Sha256Hex、鍵フィンガープリント = KeyFingerprintHex)、「幅が同じだが意味が
// 異なる」もの(公開鍵とハッシュ、署名対象ドメインごとの署名)はドメイン名を
// 残す。hex 系の別名定義はこのファイルに一元化し、同一実体への複数名を
// ファイル間で増殖させない(単一用途の長さ — nonce / ラップ暗号文等 — は
// 使用箇所のローカル定義のまま)。

import { Schema } from "effect";

/** Pattern for an exact-length lowercase-hex string (`bytes` decoded bytes). */
export function hexPattern(bytes: number): RegExp {
  return new RegExp(`^[0-9a-f]{${bytes * 2}}$`);
}

/** Schema for an exact-length lowercase-hex string (`bytes` decoded bytes). */
export function hexString(bytes: number): Schema.String {
  return Schema.String.check(
    Schema.isPattern(hexPattern(bytes), {
      description: `lowercase hex (${bytes} bytes)`,
    }),
  );
}

/** SHA-256 ハッシュ(チェーンヘッド・prev・エントリハッシュ・signed-bytes ハッシュ)。 */
export const Sha256Hex = hexString(32);

/** 32 バイト公開鍵(チェーン payload の鍵登録 — Ed25519 / X25519)。 */
export const PublicKeyHex = hexString(32);

/** X25519 暗号化公開鍵(DEK ラップの受信者鍵 — CRYPTO_SPEC §5)。 */
export const EncPubHex = hexString(32);

/** HPKE の enc(カプセル化された送信者エフェメラル公開鍵 — CRYPTO_SPEC §5)。 */
export const HpkeEncHex = hexString(32);

/** 鍵フィンガープリント(16 バイト — CRYPTO_SPEC §3)。 */
export const KeyFingerprintHex = hexString(16);

/** チェーンエントリ署名(Ed25519 — CRYPTO_SPEC §6.1)。 */
export const SignatureHex = hexString(64);

/** DEK ラップ登録署名(Ed25519 — CRYPTO_SPEC §5.1)。 */
export const WrapSignatureHex = hexString(64);

/** 値の書き込み署名(Ed25519 — CRYPTO_SPEC §4.1)。 */
export const ValueSignatureHex = hexString(64);

/** メタステートメント署名(Ed25519 — CRYPTO_SPEC §4.2)。 */
export const MetaSignatureHex = hexString(64);

/** 環境マニフェスト署名(Ed25519 — CRYPTO_SPEC §4.3)。 */
export const ManifestSignatureHex = hexString(64);

/** 招待受諾署名(Ed25519 — CRYPTO_SPEC §6.5)。 */
export const InviteAcceptSignatureHex = hexString(64);

/**
 * 1 始まりの整数(epoch / version / チェーン seq — CRYPTO_SPEC §3 / §4 / §6)。
 * hex ではないが、チェーンヘッド系フィールド(hash + seq の対)の共有定義として
 * ここに置く。
 */
export const PositiveInt = Schema.Number.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(1));
