// 署名系モジュール共通の入力検証・検証ヘルパ(dek-wrap-sign.ts / meta-sign.ts /
// value-sign.ts / meta-verify.ts / value-verify.ts)。hex は小文字・固定長のみを
// 正規形とする(大文字 hex を許すと同一データに複数の正規形が生まれ、署名・照合の
// 一意性が壊れる)。
//
// エラーの語彙(ValueInvalidReason / MetaInvalidReason / DekWrapSignatureInvalid)
// は仕様上意図的に別物なので、ここでは統合しない: 失敗時に返すエラー値・理由
// コードは呼び出し側がパラメータで注入し、本モジュールは共通の検査ロジックのみを
// 持つ。

import { decodeHex } from "./bytes.ts";
import type { ChainHistoryIndex } from "./chain-history.ts";
import type { CryptoError, CryptoResult } from "./errors.ts";
import { importSigningPublicKey } from "./keys.ts";

const SIGNATURE_BYTES = 64;
const FINGERPRINT_HEX_LENGTH = 16 * 2;
const SHA256_HEX_LENGTH = 32 * 2;
const SIGNATURE_HEX_LENGTH = SIGNATURE_BYTES * 2;

/** InvalidInput エラー値(フィールド名のみ — 秘密・入力断片を載せない)。 */
export function invalidInput(field: string): {
  readonly ok: false;
  readonly error: CryptoError;
} {
  return { ok: false, error: { kind: "InvalidInput", field } };
}

/** 指定文字数の hex 小文字文字列か(decodeHex は小文字のみ受理)。 */
export function isLowercaseHexOfLength(value: string, length: number): boolean {
  return value.length === length && decodeHex(value) !== null;
}

/**
 * Ed25519 検証の共有コア(dek-wrap-sign / meta-sign / value-sign の verify)。
 * 署名の形(64 バイト hex)の検査と WebCrypto 検証のみを担う。検証失敗と
 * WebCrypto 例外(message は入力断片を含みうるため伝播させない — errors.ts の
 * 絶対規則)は、呼び出し側が注入した `onInvalid` をそのまま返す。
 */
export async function verifyEd25519Over(
  signedBytes: Uint8Array,
  signatureHex: string,
  publicKey: CryptoKey,
  onInvalid: CryptoError,
): Promise<CryptoResult<void>> {
  const signature = decodeHex(signatureHex);
  if (signature === null || signature.length !== SIGNATURE_BYTES) {
    return invalidInput("signatureHex");
  }
  try {
    const valid = await crypto.subtle.verify(
      "Ed25519",
      publicKey,
      signature as BufferSource,
      signedBytes as BufferSource,
    );
    return valid ? { ok: true, value: undefined } : { ok: false, error: onInvalid };
  } catch {
    return { ok: false, error: onInvalid };
  }
}

/**
 * 配布検証(meta-verify / value-verify)の共有入力検査プロローグ。アクター FP
 * のフィールド名(writerKeyFingerprintHex / authorKeyFingerprintHex)だけが
 * 呼び出し側で異なるため、InvalidInput に載せる名前を注入する。
 */
export function distributedInputInvalidField(input: {
  readonly actorKeyFingerprintHex: string;
  /** InvalidInput に載せるフィールド名(例: "writerKeyFingerprintHex")。 */
  readonly actorKeyFingerprintField: string;
  readonly signatureHex: string;
  readonly predecessorSignedBytesHashHex: string | undefined;
}): string | null {
  if (!isLowercaseHexOfLength(input.actorKeyFingerprintHex, FINGERPRINT_HEX_LENGTH)) {
    return input.actorKeyFingerprintField;
  }
  if (!isLowercaseHexOfLength(input.signatureHex, SIGNATURE_HEX_LENGTH)) {
    return "signatureHex";
  }
  if (
    input.predecessorSignedBytesHashHex !== undefined &&
    !isLowercaseHexOfLength(input.predecessorSignedBytesHashHex, SHA256_HEX_LENGTH)
  ) {
    return "predecessor signedBytesHashHex";
  }
  return null;
}

/**
 * 鍵の選択(§6.3-1 前段)の共有コア: 履歴でアクターの user_id に束縛された鍵の
 * うち FP 一致のものを選択し、WebCrypto へ import する。宣言ヘッド時点の有効
 * 束縛の検査は署名検証の後(headAuthorizationReason)— 署名壊れを先に判定する
 * 検査順のため、選択自体は全 tenure を対象にする。束縛が存在しない場合は
 * 呼び出し側の語彙(writer-unknown / author-unknown)の `onUnknown` を返す。
 */
export async function importActorKeyByFingerprint(input: {
  readonly history: ChainHistoryIndex;
  readonly actorUserId: string;
  readonly actorKeyFingerprintHex: string;
  readonly onUnknown: CryptoError;
}): Promise<CryptoResult<CryptoKey>> {
  const sigPubHex = input.history.sigKeyByFingerprint(
    input.actorUserId,
    input.actorKeyFingerprintHex,
  );
  if (sigPubHex === undefined) {
    return { ok: false, error: input.onUnknown };
  }
  const keyBytes = decodeHex(sigPubHex);
  if (keyBytes === null) {
    // 検証済みチェーン由来の鍵は常に正規形 hex(到達しない防衛線)
    return { ok: false, error: input.onUnknown };
  }
  return importSigningPublicKey(keyBytes);
}

/** チェーン role の順序(§6.3-3 の認可水準比較に使う)。 */
export const ROLE_RANK = { reader: 0, member: 1, admin: 2, owner: 3 } as const;

/**
 * ヘッド束縛・認可時点検査(§6.3-1〜-3)の理由コード写像。語彙は呼び出し側
 * (ValueInvalidReason / MetaInvalidReason)が所有し、ここでは統合しない。
 */
export interface HeadAuthorizationReasons<R> {
  readonly chainHeadFuture: R;
  readonly chainHeadMismatch: R;
  readonly notMemberAtHead: R;
  readonly keyMismatchAtHead: R;
  readonly roleInsufficientAtHead: R;
}

/**
 * ヘッド束縛(§6.3-2)と認可時点(§6.3-1 / -3)の共有検査
 * (meta-verify / value-verify の headStateReason 前段):
 * - 不一致 2 種の区別: seq > 自ヘッド = future(再同期の入口)、seq ≤ 自ヘッドの
 *   ハッシュ不一致 = 分岐または偽造の硬い証拠
 * - 宣言ヘッド時点(inclusive)の在籍・鍵束縛・role。鍵不一致は remove → 別鍵
 *   re-add の tenure 跨ぎ(旧区間の鍵 × 新区間のヘッド)の拒否を含む
 * エポック整合(§6.3-4)は値署名のみの検査なので呼び出し側に残す。
 */
export function headAuthorizationReason<R>(input: {
  readonly history: ChainHistoryIndex;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string;
  readonly actorUserId: string;
  readonly actorKeyFingerprintHex: string;
  readonly requiredRoleRank: number;
  readonly reasons: HeadAuthorizationReasons<R>;
}): R | null {
  if (input.chainHeadSeq > input.history.headSeq) {
    return input.reasons.chainHeadFuture;
  }
  if (input.history.entryHashAt(input.chainHeadSeq) !== input.chainHeadHashHex) {
    return input.reasons.chainHeadMismatch;
  }
  const member = input.history.memberStateAt(input.actorUserId, input.chainHeadSeq);
  if (member === undefined) {
    return input.reasons.notMemberAtHead;
  }
  if (member.keyFingerprintHex !== input.actorKeyFingerprintHex) {
    return input.reasons.keyMismatchAtHead;
  }
  if (ROLE_RANK[member.role] < input.requiredRoleRank) {
    return input.reasons.roleInsufficientAtHead;
  }
  return null;
}
