// CRYPTO_SPEC §5.1: DEK ラップの登録署名(Ed25519)。
// signed_bytes = LP("<suite>/dek-wrap-sig", project_id, environment_id, epoch,
//                   recipient_user_id, recipient_enc_pub_hex, enc_hex,
//                   ciphertext_hex, signer_user_id)
// suite の束縛はドメイン文字列が担う(§5 の HPKE info と同型)。バイナリ列は
// §6.2 grant_server の先例どおり hex 小文字文字列として LP に載せる。
// signer_user_id は署名者自身の内部 user_id — 鍵流用による帰属の付け替えを
// 署名自体で塞ぐ(§5.1。§6.2 のメンバー鍵一意性が鍵重複メンバーの成立自体を
// 禁止した後も、独立の防衛層として維持する)。
// テストベクター: test-vectors/dek-wrap-signature.json
//
// 署名の意味論は帰属であり鮮度証明ではない(タイムスタンプ・ノンスを含めない —
// §5.1)。既存部品(Ed25519 + §2.1 LP エンコーダ)のみで構成する。

import { encodeHex } from "./bytes.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoResult } from "./errors.ts";
import { invalidInput, isLowercaseHexOfLength, verifyEd25519Over } from "./validate.ts";

const ENC_PUB_HEX_LENGTH = 32 * 2;
const HPKE_ENC_HEX_LENGTH = 32 * 2;
const WRAP_CIPHERTEXT_HEX_LENGTH = 48 * 2;

/**
 * Fields bound by a DEK-wrap registration signature (CRYPTO_SPEC §5.1):
 * the full wire form of one wrapped DEK plus its storage coordinates.
 * Binary values are carried as lowercase hex strings, exactly as on the wire.
 */
export interface DekWrapSignatureContext {
  readonly suite: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly recipientUserId: string;
  readonly recipientEncPubHex: string;
  readonly encHex: string;
  readonly ciphertextHex: string;
  /** The signer's own internal user id (binds attribution to the identity, §5.1). */
  readonly signerUserId: string;
}

// 署名対象の構造検証: epoch は LP エンコーダの前提(非負の安全な整数)、
// hex フィールドは小文字・固定長(大文字 hex を許すと同一ラップに複数の
// 正規形が生まれ、署名の一意性が壊れる)。suite / signer_user_id は非空
// (サーバー経路では Schema / 認証がより強く検証するが、公開 API として
// 空文字のドメイン・署名者を弾く)
function contextInvalidField(context: DekWrapSignatureContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (context.signerUserId.length === 0) {
    return "context signerUserId";
  }
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 0) {
    return "context epoch";
  }
  if (!isLowercaseHexOfLength(context.recipientEncPubHex, ENC_PUB_HEX_LENGTH)) {
    return "context recipientEncPubHex";
  }
  if (!isLowercaseHexOfLength(context.encHex, HPKE_ENC_HEX_LENGTH)) {
    return "context encHex";
  }
  if (!isLowercaseHexOfLength(context.ciphertextHex, WRAP_CIPHERTEXT_HEX_LENGTH)) {
    return "context ciphertextHex";
  }
  return null;
}

/**
 * Builds the canonical byte string signed for one DEK-wrap registration
 * (CRYPTO_SPEC §5.1). The domain string embeds the suite identifier, so a
 * signature never transplants across suites. Callers must validate the
 * context first (sign / verify below do); this builder assumes valid input.
 */
export function buildDekWrapSignatureBytes(context: DekWrapSignatureContext): Uint8Array {
  return encodeLengthPrefixed([
    `${context.suite}/dek-wrap-sig`,
    context.projectId,
    context.environmentId,
    context.epoch,
    context.recipientUserId,
    context.recipientEncPubHex,
    context.encHex,
    context.ciphertextHex,
    context.signerUserId,
  ]);
}

/**
 * Signs one DEK-wrap registration with the wrapper's chain signing key
 * (Ed25519, CRYPTO_SPEC §5.1). Returns the signature as lowercase hex —
 * the wire form of `WrappedDek.signatureHex` (AUTH_SPEC §12-2).
 */
export async function signDekWrap(input: {
  readonly context: DekWrapSignatureContext;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  try {
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        input.signingKey,
        buildDekWrapSignatureBytes(input.context) as BufferSource,
      ),
    );
    return { ok: true, value: encodeHex(signature) };
  } catch {
    return { ok: false, error: { kind: "SignFailed" } };
  }
}

/**
 * Verifies one DEK-wrap registration signature against the signer's Ed25519
 * public key (CRYPTO_SPEC §5.1). The server verifies with the caller's
 * chain-derived key at acceptance time; clients verify distributed wraps
 * with the key the chain history binds to the reported signer.
 */
export async function verifyDekWrapSignature(input: {
  readonly context: DekWrapSignatureContext;
  readonly signatureHex: string;
  readonly signerPublicKey: CryptoKey;
}): Promise<CryptoResult<void>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return verifyEd25519Over(
    buildDekWrapSignatureBytes(input.context),
    input.signatureHex,
    input.signerPublicKey,
    {
      kind: "DekWrapSignatureInvalid",
    },
  );
}
