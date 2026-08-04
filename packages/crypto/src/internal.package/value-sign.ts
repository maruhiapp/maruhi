// CRYPTO_SPEC §4.1: 値の書き込み署名(Ed25519)。
// value_signed_bytes = LP("<suite>/value-sig", project_id, environment_id, epoch,
//                         variable_id, version, nonce_hex, ciphertext_hex,
//                         prev_value_sig_hash_hex, writer_user_id,
//                         chain_head_hash_hex, chain_head_seq)
// suite の束縛はドメイン文字列が担う(§5.1 と同型)。数値(epoch / version /
// chain_head_seq)は §2.1 のとおり 10 進文字列化し、バイナリ列(nonce / 暗号文 /
// ハッシュ)は hex 小文字文字列として LP に載せる。
// テストベクター: test-vectors/value-signature.json
//
// 署名の意味論は「writer_user_id が、チェーン位置 (chain_head_hash, chain_head_seq)
// の状態を知った上で、この座標のこの暗号文を書いた」の帰属・内容真正性・認可時点
// 束縛である(§4.1)。平文の正しさ・鮮度は証明しない。値署名は名前を認証しない
// (名前 ↔ ID の真正性は §4.2 のメタステートメント — PR-3)。
// 宣言ヘッド・認可時点・prev 連鎖の検証は value-verify.ts(履歴照会は
// chain-history.ts)が担い、本モジュールは正規化・署名・ハッシュの低水準のみ。

import { decodeHex, encodeHex } from "./bytes.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { invalidInput, isLowercaseHexOfLength } from "./validate.ts";

const SIGNATURE_BYTES = 64;
const NONCE_HEX_LENGTH = 12 * 2;
const SHA256_HEX_LENGTH = 32 * 2;
// AES-256-GCM の ct || tag はタグ 16 バイトが下限(AUTH_SPEC §12-2 のワイヤ形状)
const MIN_CIPHERTEXT_HEX_LENGTH = 16 * 2;

/**
 * Fields bound by a value write signature (CRYPTO_SPEC §4.1): the full wire
 * form of one encrypted variable version plus its authorization anchor.
 * Binary values are carried as lowercase hex strings, exactly as on the wire.
 */
export interface ValueSignatureContext {
  readonly suite: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly epoch: number;
  readonly variableId: string;
  readonly version: number;
  readonly nonceHex: string;
  readonly ciphertextHex: string;
  /**
   * SHA-256 (lowercase hex) of the previous version's value_signed_bytes;
   * the empty string for version 1 (§4.1 の連鎖規約).
   */
  readonly prevValueSigHashHex: string;
  /** The writer's own internal user id (binds attribution to the identity). */
  readonly writerUserId: string;
  /** Entry hash of the chain head the writer last verified (§6.1). */
  readonly chainHeadHashHex: string;
  /** Seq of that head (both hash and seq are signed; mismatch fails). */
  readonly chainHeadSeq: number;
}

// 数値フィールド(epoch / version / chain_head_seq)は 1 始まりの安全な整数
function numericFieldInvalid(context: ValueSignatureContext): string | null {
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 1) {
    return "context epoch";
  }
  if (!Number.isSafeInteger(context.version) || context.version < 1) {
    return "context version";
  }
  if (!Number.isSafeInteger(context.chainHeadSeq) || context.chainHeadSeq < 1) {
    return "context chainHeadSeq";
  }
  return null;
}

// バイナリ列は hex 小文字のみ(§5.1 実装と同じ規律 — 大文字 hex を許すと
// 同一値に複数の正規形が生まれ、署名の一意性が壊れる)
function hexFieldInvalid(context: ValueSignatureContext): string | null {
  if (!isLowercaseHexOfLength(context.nonceHex, NONCE_HEX_LENGTH)) {
    return "context nonceHex";
  }
  if (
    context.ciphertextHex.length < MIN_CIPHERTEXT_HEX_LENGTH ||
    context.ciphertextHex.length % 2 !== 0 ||
    decodeHex(context.ciphertextHex) === null
  ) {
    return "context ciphertextHex";
  }
  if (
    context.prevValueSigHashHex !== "" &&
    !isLowercaseHexOfLength(context.prevValueSigHashHex, SHA256_HEX_LENGTH)
  ) {
    return "context prevValueSigHashHex";
  }
  if (!isLowercaseHexOfLength(context.chainHeadHashHex, SHA256_HEX_LENGTH)) {
    return "context chainHeadHashHex";
  }
  return null;
}

// 署名対象の構造検証。version ↔ prev の結合(version 1 = 空 / version > 1 =
// 64 hex)はここでは検査しない: 検証側は「署名は有効だが規則違反」の値
// (ベクターの rule negative v1-nonempty-prev 等)の署名をまず検証できる必要が
// あり、結合は検証規則(value-verify.ts の prev-shape-mismatch)として理由
// コード付きで拒否する。
function contextInvalidField(context: ValueSignatureContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (context.writerUserId.length === 0) {
    return "context writerUserId";
  }
  return numericFieldInvalid(context) ?? hexFieldInvalid(context);
}

/** Validates a value-signature context (shared by sign / verify / hash). */
export function valueContextInvalidField(context: ValueSignatureContext): string | null {
  return contextInvalidField(context);
}

/**
 * Builds the canonical byte string signed for one variable value version
 * (CRYPTO_SPEC §4.1). The domain string embeds the suite identifier, so a
 * signature never transplants across suites. Callers must validate the
 * context first (sign / verify / hash below do); this builder assumes valid
 * input.
 */
export function buildValueSignedBytes(context: ValueSignatureContext): Uint8Array {
  return encodeLengthPrefixed([
    `${context.suite}/value-sig`,
    context.projectId,
    context.environmentId,
    context.epoch,
    context.variableId,
    context.version,
    context.nonceHex,
    context.ciphertextHex,
    context.prevValueSigHashHex,
    context.writerUserId,
    context.chainHeadHashHex,
    context.chainHeadSeq,
  ]);
}

/**
 * SHA-256 (lowercase hex) of the canonical signed bytes — the value carried
 * as the next version's `prev_value_sig_hash_hex` (§4.1 の連鎖) and compared
 * for fork evidence (two valid signatures over distinct signed bytes at the
 * same coordinate — §14.2-5).
 */
export async function computeValueSignedBytesHash(
  context: ValueSignatureContext,
): Promise<CryptoResult<string>> {
  const field = contextInvalidField(context);
  if (field !== null) {
    return invalidInput(field);
  }
  return { ok: true, value: encodeHex(await sha256(buildValueSignedBytes(context))) };
}

/**
 * Signs one variable value version with the writer's chain signing key
 * (Ed25519, CRYPTO_SPEC §4.1). Returns the signature as lowercase hex — the
 * wire form of `EncryptedPayload.signatureHex` (AUTH_SPEC §12-2).
 *
 * Signing enforces the version ↔ prev coupling (version 1 signs an empty
 * prev, later versions sign a 64-hex prev): producing a rule-violating
 * signature is always a caller bug, unlike verification where such wire data
 * must be rejected with a typed reason instead.
 */
export async function signValue(input: {
  readonly context: ValueSignatureContext;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  if ((input.context.version === 1) !== (input.context.prevValueSigHashHex === "")) {
    return invalidInput("context prevValueSigHashHex");
  }
  try {
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        input.signingKey,
        buildValueSignedBytes(input.context) as BufferSource,
      ),
    );
    return { ok: true, value: encodeHex(signature) };
  } catch {
    return { ok: false, error: { kind: "SignFailed" } };
  }
}

/**
 * Verifies one value write signature against a writer's Ed25519 public key
 * (CRYPTO_SPEC §4.1). This is the raw signature check only — head existence,
 * head-time authorization / epoch and prev chaining are the history-based
 * checks in `verifyDistributedValue` (value-verify.ts).
 */
export async function verifyValueSignature(input: {
  readonly context: ValueSignatureContext;
  readonly signatureHex: string;
  readonly writerPublicKey: CryptoKey;
}): Promise<CryptoResult<void>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  const signature = decodeHex(input.signatureHex);
  if (signature === null || signature.length !== SIGNATURE_BYTES) {
    return invalidInput("signatureHex");
  }
  try {
    const valid = await crypto.subtle.verify(
      "Ed25519",
      input.writerPublicKey,
      signature as BufferSource,
      buildValueSignedBytes(input.context) as BufferSource,
    );
    return valid
      ? { ok: true, value: undefined }
      : { ok: false, error: { kind: "ValueInvalid", reason: "signature-invalid" } };
  } catch {
    return { ok: false, error: { kind: "ValueInvalid", reason: "signature-invalid" } };
  }
}
