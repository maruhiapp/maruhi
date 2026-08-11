// CRYPTO_SPEC §6.3(値の検証)/ §6.4(サーバー受理検証)の履歴ベース複合検証。
//
// 検証済みチェーンの履歴索引(chain-history.ts)に対して、配布(または受理)
// された値の §6.3 の 1〜4・6 を検査する:
//   1. 署名(鍵の選択 = 履歴で writer_user_id に束縛された鍵のうち FP 一致)
//   2. ヘッド束縛(seq → hash の一致。不一致 2 種 — mismatch / future — を区別)
//   3. 認可時点(宣言ヘッド時点の在籍・鍵束縛・role — tenure 跨ぎの拒否を含む)
//   4. エポック整合(宣言ヘッド時点の現エポック = 署名対象の epoch。環境作成前
//      ヘッドの拒否を含む)
//   6. 連鎖整合(predecessor を渡された場合のみ: prev 一致 + エポック非減少)
// 座標整合(§6.3-5)は呼び出し側の責務: 本関数へ渡す context 自体を、申告値
// でなく期待座標(検証済み genesis ハッシュ・要求環境・応答メタの variableId 等)
// から構成すること(セッション 11 の CLI 検証と同じ姿勢)。
//
// latest-only の限界(session-14 裁定 B): predecessor が無い場合でも署名・
// ヘッド・鍵・role・環境・エポック・prev の形は必ず検査する。prev の実在一致と
// エポック非減少は predecessor が渡された場合のみ検査し、渡されない場合に
// 「検査済み」と偽らない(呼び出し側は §14.3 の非保証を負う)。
// 検査順序は仮裁定 C(署名壊れ → unknown head → state mismatch)に一致する。

import type { ChainHistoryIndex } from "./chain-history.ts";
import type { CryptoResult, ValueInvalidReason } from "./errors.ts";
import {
  distributedInputInvalidField,
  headAuthorizationReason,
  importActorKeyByFingerprint,
  invalidInput,
  ROLE_RANK,
} from "./validate.ts";
import {
  computeValueSignedBytesHash,
  valueContextInvalidField,
  type ValueSignatureContext,
  verifyValueSignature,
} from "./value-sign.ts";

/**
 * The verified predecessor version's anchor (§6.3-6): its
 * value_signed_bytes hash and its epoch. The caller must have verified the
 * predecessor itself (server: stored acceptance-time values; client: a value
 * that passed this same verification) — chaining onto unverified data would
 * poison the evidence chain (AUTH_SPEC §12-5 の 409 規律と同根).
 */
export interface ValuePredecessor {
  readonly signedBytesHashHex: string;
  readonly epoch: number;
}

/** Input of the history-based distributed-value verification (§6.3 / §6.4). */
export interface DistributedValueInput {
  /** Index over the verifier's own fully verified chain snapshot. */
  readonly history: ChainHistoryIndex;
  /** Expected coordinates + wire payload fields (see module comment). */
  readonly context: ValueSignatureContext;
  /** Distributed writer key fingerprint (server: acceptance-time caller FP). */
  readonly writerKeyFingerprintHex: string;
  readonly signatureHex: string;
  /** Verified previous version, when the verifier holds one (裁定 B). */
  readonly predecessor?: ValuePredecessor | undefined;
}

function valueInvalid(reason: ValueInvalidReason): {
  readonly ok: false;
  readonly error: { readonly kind: "ValueInvalid"; readonly reason: ValueInvalidReason };
} {
  return { ok: false, error: { kind: "ValueInvalid", reason } };
}

// 2〜3. ヘッド束縛・認可時点(§6.3-1〜-3)の理由コード写像。検査本体は
// headAuthorizationReason(validate.ts — meta-verify と共有)
const HEAD_AUTHORIZATION_REASONS = {
  chainHeadFuture: "chain-head-future",
  chainHeadMismatch: "chain-head-mismatch",
  notMemberAtHead: "writer-not-member-at-head",
  keyMismatchAtHead: "writer-key-mismatch-at-head",
  roleInsufficientAtHead: "writer-role-insufficient-at-head",
} as const satisfies Record<string, ValueInvalidReason>;

function headStateReason(input: DistributedValueInput): ValueInvalidReason | null {
  const { history, context } = input;
  const authorization = headAuthorizationReason({
    history,
    chainHeadSeq: context.chainHeadSeq,
    chainHeadHashHex: context.chainHeadHashHex,
    actorUserId: context.writerUserId,
    actorKeyFingerprintHex: input.writerKeyFingerprintHex,
    requiredRoleRank: ROLE_RANK.member,
    reasons: HEAD_AUTHORIZATION_REASONS,
  });
  if (authorization !== null) {
    return authorization;
  }
  // 4. エポック整合(§6.3-4): 環境作成前ヘッドは拒否(既定値フォールバック禁止)
  const environment = history.environmentStateAt(context.environmentId, context.chainHeadSeq);
  if (environment === undefined) {
    return "environment-not-created-at-head";
  }
  if (environment.currentEpoch !== context.epoch) {
    return "epoch-not-current-at-head";
  }
  return null;
}

function prevReason(input: DistributedValueInput): ValueInvalidReason | null {
  const { context, predecessor } = input;
  // prev の形(裁定 B: latest-only でも必ず検査): version 1 = 空、> 1 = 64 hex。
  // 個別フィールドの hex 形式は valueContextInvalidField が検査済みなので、
  // ここは version との結合のみ
  if ((context.version === 1) !== (context.prevValueSigHashHex === "")) {
    return "prev-shape-mismatch";
  }
  if (predecessor === undefined) {
    return null;
  }
  // 6. 連鎖整合(§6.3-6): prev の実在一致とエポック非減少(§4.1 の単調性)。
  //    prev 不一致を Ed25519 failure に潰さない(裁定 B / C)
  if (context.prevValueSigHashHex !== predecessor.signedBytesHashHex) {
    return "prev-hash-mismatch";
  }
  if (context.epoch < predecessor.epoch) {
    return "epoch-regressed";
  }
  return null;
}

/**
 * Verifies one distributed (or submitted) variable value against a verified
 * chain history (CRYPTO_SPEC §6.3 / §6.4). Returns the value's
 * signed-bytes hash on success — the anchor for the next version's prev
 * chain and for same-coordinate fork evidence (§14.2-5).
 *
 * The client passes the distributed writer identity; the server passes the
 * calling principal's acceptance-time chain member identity (§12-5: the
 * head-time key binding must then equal the acceptance-time key, which is
 * exactly the `writer-key-mismatch-at-head` check).
 */
export async function verifyDistributedValue(
  input: DistributedValueInput,
): Promise<CryptoResult<{ readonly signedBytesHashHex: string }>> {
  const field =
    valueContextInvalidField(input.context) ??
    distributedInputInvalidField({
      actorKeyFingerprintHex: input.writerKeyFingerprintHex,
      actorKeyFingerprintField: "writerKeyFingerprintHex",
      signatureHex: input.signatureHex,
      predecessorSignedBytesHashHex: input.predecessor?.signedBytesHashHex,
    });
  if (field !== null) {
    return invalidInput(field);
  }

  // 1. 鍵の選択(§6.3-1 前段。検査順 = 仮裁定 C): validate.ts の共有コア
  const imported = await importActorKeyByFingerprint({
    history: input.history,
    actorUserId: input.context.writerUserId,
    actorKeyFingerprintHex: input.writerKeyFingerprintHex,
    onUnknown: { kind: "ValueInvalid", reason: "writer-unknown" },
  });
  if (!imported.ok) {
    return imported;
  }
  const signature = await verifyValueSignature({
    context: input.context,
    signatureHex: input.signatureHex,
    writerPublicKey: imported.value,
  });
  if (!signature.ok) {
    return signature;
  }

  const headReason = headStateReason(input);
  if (headReason !== null) {
    return valueInvalid(headReason);
  }
  const chainReason = prevReason(input);
  if (chainReason !== null) {
    return valueInvalid(chainReason);
  }

  const hash = await computeValueSignedBytesHash(input.context);
  if (!hash.ok) {
    return hash;
  }
  return { ok: true, value: { signedBytesHashHex: hash.value } };
}
