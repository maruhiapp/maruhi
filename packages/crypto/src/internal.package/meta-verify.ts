// CRYPTO_SPEC §6.3(メタデータステートメントの検証)/ §6.4(サーバー受理検証)の
// 履歴ベース複合検証。value-verify.ts の同型(session-14 の申し送り — 検証機構を
// 二重実装しない)。
//
// 検証済みチェーンの履歴索引(chain-history.ts)に対して、配布(または受理)
// されたステートメントの §6.3 の 1〜3・6 を検査する:
//   1. 署名(鍵の選択 = 履歴で author_user_id に束縛された鍵のうち FP 一致)
//   2. ヘッド束縛(seq → hash の一致。不一致 2 種 — mismatch / future — を区別)
//   3. 認可時点(宣言ヘッド時点の在籍・鍵束縛・role — tenure 跨ぎの拒否を含む。
//      role 水準: 変数の作成・rename・削除と環境の作成・rename = member 以上、
//      環境の削除のみ admin 以上 — §4.2 / AUTH_SPEC §12-3)
//   6. 連鎖整合(predecessor を渡された場合のみ: prev 一致 + 削除後の再ステート
//      メント拒否 — §4.2 の「deleted 後の再 active 化は禁止」)
// 座標整合(§6.3-5)は呼び出し側の責務: 本関数へ渡す context 自体を、申告値
// でなく期待座標(検証済み genesis ハッシュ・要求環境・応答外側の variableId)
// から構成すること。
//
// **エポック整合(§6.3-4)は存在しない**: メタステートメントはエポックアンカーを
// 持たず(§4.2)、環境の存在も検査しない(AUTH_SPEC §12-4 — 複合環境作成の同梱
// ステートメントの宣言ヘッド時点に環境は未存在。値署名との意図された非対称)。
// この構造的帰結として、前進 meta_version への偽ステートメント注入(在籍区間内の
// 宣言ヘッド)は署名・連鎖検証を通る — v1 の明示的な残余(§14.3-5。fork 証拠化
// = prev 連鎖の分岐までが本 PR の保証)。
//
// latest-only の限界(session-14 裁定 B の同型): predecessor が無い場合でも
// 署名・ヘッド・鍵・role・prev の形は必ず検査する。prev の実在一致と削除後の
// 再ステートメント拒否は predecessor が渡された場合のみ検査し、渡されない場合に
// 「検査済み」と偽らない(呼び出し側は §14.3 の非保証を負う)。

import { decodeHex } from "./bytes.ts";
import type { ChainHistoryIndex } from "./chain-history.ts";
import type { CryptoResult, MetaInvalidReason } from "./errors.ts";
import { importSigningPublicKey } from "./keys.ts";
import {
  computeMetaSignedBytesHash,
  metaContextInvalidField,
  type MetaStatementContext,
  type MetaStatementStatus,
  verifyMetaStatementSignature,
} from "./meta-sign.ts";
import { invalidInput, isLowercaseHexOfLength } from "./validate.ts";

const FINGERPRINT_HEX_LENGTH = 16 * 2;
const SHA256_HEX_LENGTH = 32 * 2;
const SIGNATURE_HEX_LENGTH = 64 * 2;

/**
 * The verified predecessor statement's anchor (§6.3-6): its signed-bytes
 * hash and its status. The caller must have verified the predecessor itself
 * (server: stored acceptance-time statements; client: a statement that
 * passed this same verification) — chaining onto unverified data would
 * poison the evidence chain (AUTH_SPEC §12-5 の 409 規律と同根).
 */
export interface MetaPredecessor {
  readonly signedBytesHashHex: string;
  readonly status: MetaStatementStatus;
}

/** Input of the history-based distributed-statement verification (§6.3 / §6.4). */
export interface DistributedMetaStatementInput {
  /** Index over the verifier's own fully verified chain snapshot. */
  readonly history: ChainHistoryIndex;
  /** Expected coordinates + wire statement fields (see module comment). */
  readonly context: MetaStatementContext;
  /** Distributed author key fingerprint (server: acceptance-time caller FP). */
  readonly authorKeyFingerprintHex: string;
  readonly signatureHex: string;
  /** Verified previous statement, when the verifier holds one (裁定 B 同型). */
  readonly predecessor?: MetaPredecessor | undefined;
}

function metaInvalid(reason: MetaInvalidReason): {
  readonly ok: false;
  readonly error: { readonly kind: "MetaStatementInvalid"; readonly reason: MetaInvalidReason };
} {
  return { ok: false, error: { kind: "MetaStatementInvalid", reason } };
}

const ROLE_RANK = { reader: 0, member: 1, admin: 2, owner: 3 } as const;

/** §4.2 / §12-3 の role 水準: 環境の削除のみ admin、それ以外は member。 */
function requiredRoleRank(context: MetaStatementContext): number {
  return context.target.kind === "environment" && context.status === "deleted"
    ? ROLE_RANK.admin
    : ROLE_RANK.member;
}

function headStateReason(input: DistributedMetaStatementInput): MetaInvalidReason | null {
  const { history, context } = input;
  // 2. ヘッド束縛(§6.3-2): 不一致 2 種の区別。seq > 自ヘッド = future(再同期の
  //    入口)、seq ≤ 自ヘッドのハッシュ不一致 = 分岐または偽造の硬い証拠
  if (context.chainHeadSeq > history.headSeq) {
    return "chain-head-future";
  }
  if (history.entryHashAt(context.chainHeadSeq) !== context.chainHeadHashHex) {
    return "chain-head-mismatch";
  }
  // 3. 認可時点(§6.3-1 / -3): 宣言ヘッド時点(inclusive)の在籍・鍵束縛・role
  const member = history.memberStateAt(context.authorUserId, context.chainHeadSeq);
  if (member === undefined) {
    return "author-not-member-at-head";
  }
  if (member.keyFingerprintHex !== input.authorKeyFingerprintHex) {
    // remove → 別鍵 re-add の tenure 跨ぎ(旧区間の鍵 × 新区間のヘッド)を拒否
    return "author-key-mismatch-at-head";
  }
  if (ROLE_RANK[member.role] < requiredRoleRank(context)) {
    return "author-role-insufficient-at-head";
  }
  // エポック整合(§6.3-4)はメタに存在しない(モジュール冒頭コメント参照)
  return null;
}

function prevReason(input: DistributedMetaStatementInput): MetaInvalidReason | null {
  const { context, predecessor } = input;
  // prev の形(latest-only でも必ず検査): metaVersion 1 = 空、> 1 = 64 hex。
  // 個別フィールドの hex 形式は metaContextInvalidField が検査済みなので、
  // ここは metaVersion との結合のみ
  if ((context.metaVersion === 1) !== (context.prevMetaSigHashHex === "")) {
    return "prev-shape-mismatch";
  }
  if (predecessor === undefined) {
    return null;
  }
  // 6. 連鎖整合(§6.3-6): prev の実在一致。prev 不一致を Ed25519 failure に
  //    潰さない(value-verify と同じ裁定)
  if (context.prevMetaSigHashHex !== predecessor.signedBytesHashHex) {
    return "prev-hash-mismatch";
  }
  // §4.2: deleted 後の再 active 化は禁止(tombstone は終端)。deleted の後続は
  // status を問わずすべて拒否する — 削除済み変数・環境の無断復活の遮断
  if (predecessor.status === "deleted") {
    return "revived-after-delete";
  }
  return null;
}

/**
 * Verifies one distributed (or submitted) metadata statement against a
 * verified chain history (CRYPTO_SPEC §6.3 / §6.4). Returns the statement's
 * signed-bytes hash on success — the anchor for the next metaVersion's prev
 * chain and for same-coordinate fork evidence (§14.2-5).
 *
 * The client passes the distributed author identity; the server passes the
 * calling principal's acceptance-time chain member identity (§12-5: the
 * head-time key binding must then equal the acceptance-time key, which is
 * exactly the `author-key-mismatch-at-head` check).
 */
export async function verifyDistributedMetaStatement(
  input: DistributedMetaStatementInput,
): Promise<CryptoResult<{ readonly signedBytesHashHex: string }>> {
  const field = metaContextInvalidField(input.context);
  if (field !== null) {
    return invalidInput(field);
  }
  if (!isLowercaseHexOfLength(input.authorKeyFingerprintHex, FINGERPRINT_HEX_LENGTH)) {
    return invalidInput("authorKeyFingerprintHex");
  }
  if (!isLowercaseHexOfLength(input.signatureHex, SIGNATURE_HEX_LENGTH)) {
    return invalidInput("signatureHex");
  }
  if (
    input.predecessor !== undefined &&
    !isLowercaseHexOfLength(input.predecessor.signedBytesHashHex, SHA256_HEX_LENGTH)
  ) {
    return invalidInput("predecessor signedBytesHashHex");
  }

  // 1. 鍵の選択(§6.3-1 前段): 履歴で author_user_id に束縛された鍵のうち FP
  //    一致。宣言ヘッド時点の有効束縛の検査は署名検証の後(headStateReason)—
  //    署名壊れを先に判定する検査順のため、選択自体は全 tenure を対象にする
  const sigPubHex = input.history.sigKeyByFingerprint(
    input.context.authorUserId,
    input.authorKeyFingerprintHex,
  );
  if (sigPubHex === undefined) {
    return metaInvalid("author-unknown");
  }
  const keyBytes = decodeHex(sigPubHex);
  if (keyBytes === null) {
    // 検証済みチェーン由来の鍵は常に正規形 hex(到達しない防衛線)
    return metaInvalid("author-unknown");
  }
  const imported = await importSigningPublicKey(keyBytes);
  if (!imported.ok) {
    return imported;
  }
  const signature = await verifyMetaStatementSignature({
    context: input.context,
    signatureHex: input.signatureHex,
    authorPublicKey: imported.value,
  });
  if (!signature.ok) {
    return signature;
  }

  const headReason = headStateReason(input);
  if (headReason !== null) {
    return metaInvalid(headReason);
  }
  const chainReason = prevReason(input);
  if (chainReason !== null) {
    return metaInvalid(chainReason);
  }

  const hash = await computeMetaSignedBytesHash(input.context);
  if (!hash.ok) {
    return hash;
  }
  return { ok: true, value: { signedBytesHashHex: hash.value } };
}
