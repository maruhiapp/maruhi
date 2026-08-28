// CRYPTO_SPEC §6.6: ヘッド申告(Ed25519)。
// head_attestation_signed_bytes = LP("<suite>/head-attestation",
//                                    project_id, attester_user_id,
//                                    chain_head_hash_hex, chain_head_seq)
// suite の束縛はドメイン文字列が担う(§5.1 と同型)。バイナリ列(ヘッドハッシュ)は
// hex 小文字文字列として LP に載せ、数値(chain_head_seq)は §2.1 のとおり
// 10 進文字列化する。テストベクター: test-vectors/head-attestation.json
//
// 意味論は「attester_user_id が、このプロジェクトのチェーンをこの位置まで
// 検証済みとして受理した」の帰属・文脈束縛(§6.6)。チェーンヘッド自体の真正性は
// 証明しない — 検証は受信側が自ビューと照合して行う(§6.3 のヘッドゴシップ)。
// タイムスタンプ・ノンスは署名対象に含めない(鮮度証明ではない — 申告の新旧は
// chain_head_seq が順序付け、古い申告の再配布はサーバーの omission と等価 = G8)。
// attester_user_id の焼き込みは §5.1 の signer_user_id と同じ帰属付け替え対策。
//
// 履歴ベースの検証(verifyDistributedHeadAttestation)は value / meta の同型
// (検証機構を二重実装しない — validate.ts の共有コア)。**attester が自ビューの
// 現メンバーであること(§6.6 (1) の前半)は本モジュールの検査対象外**: それは
// 「配布・照合の対象か」の選別であって申告自体の有効性ではなく(削除済み
// メンバーの在籍中ヘッドへの過去申告は検証を通る — ベクター
// removed-attester-in-tenure)、呼び出し側が history.memberStateAt(userId,
// history.headSeq) で先に選別する。

import { encodeHex } from "./bytes.ts";
import type { ChainHistoryIndex } from "./chain-history.ts";
import { encodeLengthPrefixed } from "./encoding.ts";
import type { AttestationInvalidReason, CryptoResult } from "./errors.ts";
import { sha256 } from "./hash.ts";
import {
  distributedInputInvalidField,
  headAuthorizationReason,
  type HeadAuthorizationReasons,
  importActorKeyByFingerprint,
  invalidInput,
  isLowercaseHexOfLength,
  ROLE_RANK,
  signEd25519Over,
  verifyEd25519Over,
} from "./validate.ts";

const SHA256_HEX_LENGTH = 32 * 2;

/**
 * Fields bound by a head attestation (CRYPTO_SPEC §6.6): the project
 * coordinate, the attester's identity, and the verified chain head (hash +
 * seq — both are signed, so a mismatched pair never verifies). Binary values
 * are carried as lowercase hex strings, exactly as on the wire.
 */
export interface HeadAttestationContext {
  readonly suite: string;
  readonly projectId: string;
  /** The attester's own internal user id (binds attribution — §5.1 と同型). */
  readonly attesterUserId: string;
  /** Entry hash of the chain head the attester verified (§6.1). */
  readonly chainHeadHashHex: string;
  /** Seq of that head. */
  readonly chainHeadSeq: number;
}

// 署名対象の構造検証: hex は小文字・固定長のみ(大文字 hex を許すと同一申告に
// 複数の正規形が生まれ、署名の一意性が壊れる — validate.ts の規律)。
// chain_head_seq は §2.1 の数値境界(非負の安全整数)+ seq 1 始まり
function contextInvalidField(context: HeadAttestationContext): string | null {
  if (context.suite.length === 0) {
    return "context suite";
  }
  if (context.projectId.length === 0) {
    return "context projectId";
  }
  if (context.attesterUserId.length === 0) {
    return "context attesterUserId";
  }
  if (!isLowercaseHexOfLength(context.chainHeadHashHex, SHA256_HEX_LENGTH)) {
    return "context chainHeadHashHex";
  }
  if (!Number.isSafeInteger(context.chainHeadSeq) || context.chainHeadSeq < 1) {
    return "context chainHeadSeq";
  }
  return null;
}

/**
 * Builds the canonical byte string signed for one head attestation
 * (CRYPTO_SPEC §6.6). The domain string embeds the suite identifier, so a
 * signature never transplants across suites; project_id binds the context, so
 * an attestation never transplants across projects. Callers must validate the
 * context first (sign / verify below do); this builder assumes valid input.
 */
export function buildHeadAttestationSignedBytes(context: HeadAttestationContext): Uint8Array {
  return encodeLengthPrefixed([
    `${context.suite}/head-attestation`,
    context.projectId,
    context.attesterUserId,
    context.chainHeadHashHex,
    context.chainHeadSeq,
  ]);
}

/**
 * SHA-256 (lowercase hex) of the canonical signed bytes — the digest a
 * verifier records as evidence when a distributed attestation contradicts its
 * own view (§6.6 / §14.2-5 の証拠化).
 */
export async function computeHeadAttestationSignedBytesHash(
  context: HeadAttestationContext,
): Promise<CryptoResult<string>> {
  const field = contextInvalidField(context);
  if (field !== null) {
    return invalidInput(field);
  }
  return { ok: true, value: encodeHex(await sha256(buildHeadAttestationSignedBytes(context))) };
}

/**
 * Signs one head attestation with the attester's chain signing key (Ed25519,
 * CRYPTO_SPEC §6.6). Returns the signature as lowercase hex — the wire form
 * of the submission's `signatureHex` (AUTH_SPEC §16-1).
 */
export async function signHeadAttestation(input: {
  readonly context: HeadAttestationContext;
  readonly signingKey: CryptoKey;
}): Promise<CryptoResult<string>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return signEd25519Over(buildHeadAttestationSignedBytes(input.context), input.signingKey);
}

/**
 * Verifies one head-attestation signature against an attester's Ed25519
 * public key (CRYPTO_SPEC §6.6). This is the raw signature check only — head
 * binding and head-time membership are the history-based checks in
 * `verifyDistributedHeadAttestation`.
 */
export async function verifyHeadAttestationSignature(input: {
  readonly context: HeadAttestationContext;
  readonly signatureHex: string;
  readonly attesterPublicKey: CryptoKey;
}): Promise<CryptoResult<void>> {
  const field = contextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  return verifyEd25519Over(
    buildHeadAttestationSignedBytes(input.context),
    input.signatureHex,
    input.attesterPublicKey,
    { kind: "HeadAttestationInvalid", reason: "signature-invalid" },
  );
}

/** Input of the history-based distributed-attestation verification (§6.6). */
export interface DistributedHeadAttestationInput {
  /** Index over the verifier's own fully verified chain snapshot. */
  readonly history: ChainHistoryIndex;
  /** Expected coordinates + wire attestation fields (§6.3-5 の座標整合は呼び出し側)。 */
  readonly context: HeadAttestationContext;
  /** Distributed attester key fingerprint (server: acceptance-time member FP). */
  readonly attesterKeyFingerprintHex: string;
  readonly signatureHex: string;
}

function attestationInvalid(reason: AttestationInvalidReason): {
  readonly ok: false;
  readonly error: {
    readonly kind: "HeadAttestationInvalid";
    readonly reason: AttestationInvalidReason;
  };
} {
  return { ok: false, error: { kind: "HeadAttestationInvalid", reason } };
}

// ヘッド束縛・申告ヘッド時点の在籍(§6.6 (1)〜(3))の理由コード写像。検査本体は
// headAuthorizationReason(validate.ts — value / meta と共有)。必要 role の
// 下限は reader(全メンバーが申告できる — §6.3 ヘッドゴシップ)なので
// roleInsufficientAtHead は構造的に発火しない(ROLE_RANK.reader = 最下位)—
// 写像は在籍不一致側の理由に畳んでおく
const HEAD_ATTESTATION_REASONS = {
  chainHeadFuture: "chain-head-future",
  chainHeadMismatch: "chain-head-mismatch",
  notMemberAtHead: "attester-not-member-at-head",
  keyMismatchAtHead: "attester-key-mismatch-at-head",
  roleInsufficientAtHead: "attester-not-member-at-head",
} as const satisfies HeadAuthorizationReasons<AttestationInvalidReason>;

/**
 * Verifies one distributed (or submitted) head attestation against a
 * verified chain history (CRYPTO_SPEC §6.6): key selection by (user id,
 * fingerprint) over the full history, the Ed25519 signature, then the head
 * binding with the §6.3-2 two-way distinction and the head-time (inclusive)
 * membership / key-binding checks. Returns the signed-bytes hash on success
 * (the evidence anchor — §14.2-5).
 *
 * The reason codes drive the gossip reconciliation (§6.3 ヘッドゴシップ):
 * `chain-head-mismatch` = the hard-evidence branch (a) — the caller must
 * treat the *attestation itself* as evidence (署名は検証済み), not merely
 * discard it; `chain-head-future` = the bounded-resync branch (b); any other
 * reason = an invalid attestation that must NOT be used as照合材料
 * (偽申告による警告誘発の排除 — §6.6).
 *
 * The current-membership gate of §6.6 (1) is the caller's selection step
 * (see the module comment) — a removed attester's in-tenure attestation
 * verifies here by design (ベクター removed-attester-in-tenure).
 */
export async function verifyDistributedHeadAttestation(
  input: DistributedHeadAttestationInput,
): Promise<CryptoResult<{ readonly signedBytesHashHex: string }>> {
  const field =
    contextInvalidField(input.context) ??
    distributedInputInvalidField({
      actorKeyFingerprintHex: input.attesterKeyFingerprintHex,
      actorKeyFingerprintField: "attesterKeyFingerprintHex",
      signatureHex: input.signatureHex,
      predecessorSignedBytesHashHex: undefined,
    });
  if (field !== null) {
    return invalidInput(field);
  }

  // 鍵の選択(§6.6 (2) 前段。検査順は value / meta と同一: 署名壊れを先に判定
  // するため、選択は全 tenure を対象にし、ヘッド時点の束縛は後段で検査する)
  const imported = await importActorKeyByFingerprint({
    history: input.history,
    actorUserId: input.context.attesterUserId,
    actorKeyFingerprintHex: input.attesterKeyFingerprintHex,
    onUnknown: { kind: "HeadAttestationInvalid", reason: "attester-unknown" },
  });
  if (!imported.ok) {
    return imported;
  }
  const signature = await verifyHeadAttestationSignature({
    context: input.context,
    signatureHex: input.signatureHex,
    attesterPublicKey: imported.value,
  });
  if (!signature.ok) {
    return signature;
  }

  const headReason = headAuthorizationReason({
    history: input.history,
    chainHeadSeq: input.context.chainHeadSeq,
    chainHeadHashHex: input.context.chainHeadHashHex,
    actorUserId: input.context.attesterUserId,
    actorKeyFingerprintHex: input.attesterKeyFingerprintHex,
    requiredRoleRank: ROLE_RANK.reader,
    reasons: HEAD_ATTESTATION_REASONS,
  });
  if (headReason !== null) {
    return attestationInvalid(headReason);
  }

  return {
    ok: true,
    value: {
      signedBytesHashHex: encodeHex(await sha256(buildHeadAttestationSignedBytes(input.context))),
    },
  };
}
