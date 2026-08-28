// CRYPTO_SPEC §4.3 / §6.3(環境マニフェストの検証)/ §6.4(サーバー受理検証)の
// 履歴ベース複合検証。value-verify.ts / meta-verify.ts の同型(検証機構を
// 二重実装しない — サーバー / CLI が共有する唯一の実装。§4.3 の「正規形実装は
// packages/crypto に 1 つだけ置く」)。
//
// 検証済みチェーンの履歴索引(chain-history.ts)に対して、配布(または受理)
// されたマニフェストの §6.3 の 1〜3・5 同型 + エポック整合 + ダイジェスト再計算を
// 検査する:
//   1. 署名(鍵の選択 = 履歴で issuer_user_id に束縛された鍵のうち FP 一致)
//   2. ヘッド束縛(seq → hash の一致。不一致 2 種 — mismatch / future — を区別)
//   3. 認可時点(宣言ヘッド時点の在籍・鍵束縛・role — 発行契機はすべて member
//      以上のメタ操作 — §4.3)
//   4. エポック整合(§4.3 (2)。2026-08-27 セッション 33 で改訂 — 旧 H+1 例外の
//      廃止。session-32 §5-1 = 所有者承認済み案 2-G′): 検証済みチェーン上に当該
//      (environment_id, manifest_version) の `checkpoint` タプルが存在する場合、
//      その (epoch, manifest_sig_hash) と**完全一致しなければならない**(境界
//      チェックポイント束縛 — strict はこの場合の代替経路に**ならない**。
//      環境作成・rotate 複合のマニフェストは複合が必須同梱する境界 checkpoint —
//      AUTH_SPEC §12-4 — のこの経路で検証される)。同座標に (epoch,
//      manifest_sig_hash) の異なるタプルが併存する場合は equivocation の硬い
//      証拠として拒否する。タプルが存在しない場合のみ、宣言ヘッド時点の当該
//      環境の現エポックとの厳密一致(strict)
//   5. 環境メタ整合: (env_meta_version, env_meta_sig_hash_hex) = 検証済み環境
//      メタステートメントの最新形(AUTH_SPEC §12-5 (7) の再計算対象)
//   6. ダイジェスト再計算(§4.3 (3)): 検証済み全ステートメント(tombstone 込み)
//      からの variables_digest 再計算一致。不一致 = 欠落・注入・順序違反の検出
//   7. prev 連鎖(predecessor を渡された場合のみ: prev 一致 + **エポック非減少**
//      — 値の §4.1 単調性のマニフェスト版。rotate 後に旧エポックを焼き込んだ
//      前進 manifestVersion の検出 = 本機構の核)
//   8. チェックポイント整合の規則 1(§6.3 / §4.3 (4)): manifestVersion・epoch は
//      当該環境の**最新** `checkpoint` 基準以上であること(基準割れ = チェック
//      ポイント済み状態からの巻き戻しとして拒否。タプルを持つ版への (4) の照合の
//      下方回避もこれが塞ぐ — 検査順序〔束縛 (4) → 本規則〕はベクター
//      checkpoint-binding-mismatch / checkpoint-regressed が固定)。
//      同版・異ハッシュは (4) の束縛(基準 = 最新 checkpoint 自身のタプル)が拒否
// 座標整合(§6.3-5)は呼び出し側の責務: 本関数へ渡す context 自体を、申告値
// でなく期待座標(検証済み genesis ハッシュ・要求環境)から構成すること。
// entries / envMeta も**検証済み**ステートメントから構成すること(サーバー =
// 受理後状態の保存行、クライアント = §6.3 検証を通過した配布ステートメント)。
//
// チェックポイント束縛(4)の照合材料は履歴索引の内部照会(checkpointTupleFor —
// session-33 裁定 A)であり、呼び出し側の入力ではない: 明示入力の形は「引き
// 忘れ = strict へのフォールバック」という fail-open(タプルが存在しても strict
// 経路が生きたままなら equivocation 優位が消える — session-32 §4-2 が選言形を
// 潰した理由の再現)を呼び出し規約のバグとして許すため、構造的に閉じる。
//
// latest-only の限界(session-14 裁定 B の同型): predecessor が無い場合でも
// 署名・ヘッド・鍵・role・エポック・環境メタ・ダイジェスト・prev の形は必ず
// 検査する。prev の実在一致とエポック非減少は predecessor が渡された場合のみ
// 検査し、渡されない場合に「検査済み」と偽らない(呼び出し側は §14.3 の非保証を
// 負う — 床のマニフェスト拡張・チェックポイント整合が補完する)。

import { encodeHex } from "./bytes.ts";
import type { ChainHistoryIndex } from "./chain-history.ts";
import type { CryptoResult, ManifestInvalidReason } from "./errors.ts";
import { sha256 } from "./hash.ts";
import {
  buildEnvManifestSignedBytes,
  computeVariablesDigest,
  type EnvManifestContext,
  manifestContextInvalidField,
  type VariablesDigestEntry,
  verifyEnvManifestSignature,
} from "./manifest-sign.ts";
import {
  distributedInputInvalidField,
  headAuthorizationReason,
  type HeadAuthorizationReasons,
  importActorKeyByFingerprint,
  invalidInput,
  ROLE_RANK,
} from "./validate.ts";

/**
 * The verified predecessor manifest's anchor (§4.3 の連鎖): its signed-bytes
 * hash and its epoch. The caller must have verified the predecessor itself
 * (server: the stored latest manifest; client: a manifest that passed this
 * same verification / the local floor's manifest record) — chaining onto
 * unverified data would poison the evidence chain.
 */
export interface EnvManifestPredecessor {
  readonly signedBytesHashHex: string;
  readonly epoch: number;
}

/** The latest verified environment meta statement the manifest must bind. */
export interface EnvManifestEnvMeta {
  readonly metaVersion: number;
  readonly sigHashHex: string;
}

/** Input of the history-based distributed-manifest verification (§4.3 / §6.3 / §6.4). */
export interface DistributedEnvManifestInput {
  /** Index over the verifier's own fully verified chain snapshot. */
  readonly history: ChainHistoryIndex;
  /** Expected coordinates + wire manifest fields (see module comment). */
  readonly context: EnvManifestContext;
  /** Distributed issuer key fingerprint (server: acceptance-time caller FP). */
  readonly issuerKeyFingerprintHex: string;
  readonly signatureHex: string;
  /**
   * The **verified** statement set the digest is recomputed from — every
   * variable's latest statement including tombstones (§4.3 (3)).
   */
  readonly entries: readonly VariablesDigestEntry[];
  /** The **verified** latest environment meta statement (§12-5 (7)). */
  readonly envMeta: EnvManifestEnvMeta;
  /** Verified previous manifest, when the verifier holds one (裁定 B 同型). */
  readonly predecessor?: EnvManifestPredecessor | undefined;
}

function manifestInvalid(reason: ManifestInvalidReason): {
  readonly ok: false;
  readonly error: { readonly kind: "EnvManifestInvalid"; readonly reason: ManifestInvalidReason };
} {
  return { ok: false, error: { kind: "EnvManifestInvalid", reason } };
}

// 2〜3. ヘッド束縛・認可時点(§6.3-1〜-3)の理由コード写像。検査本体は
// headAuthorizationReason(validate.ts — value-verify / meta-verify と共有)
const HEAD_AUTHORIZATION_REASONS = {
  chainHeadFuture: "chain-head-future",
  chainHeadMismatch: "chain-head-mismatch",
  notMemberAtHead: "issuer-not-member-at-head",
  keyMismatchAtHead: "issuer-key-mismatch-at-head",
  roleInsufficientAtHead: "issuer-role-insufficient-at-head",
} as const satisfies HeadAuthorizationReasons<ManifestInvalidReason>;

/**
 * 4. エポック整合(§4.3 (2) — チェックポイント束縛。2026-08-27 改訂で旧 H+1
 * 例外を廃止)。タプルが存在する場合の照合は (epoch, manifest_sig_hash) の
 * **両方**に対して行う: ハッシュはエポックを署名対象として覆うが、タプル側の
 * epoch フィールドがマニフェスト内容と矛盾する形(チェーンに載った虚偽公証)は
 * ハッシュ照合だけでは検出されない。タプルが存在する場合、宣言ヘッド時点の
 * 環境存在検査は行わない(環境作成複合の正当な形 — 宣言ヘッド H の時点で環境は
 * 未作成、H+1 の create と H+2 の境界 checkpoint が同一トランザクションで載る)。
 */
function epochIntegrityReason(
  input: DistributedEnvManifestInput,
  signedBytesHashHex: string,
): ManifestInvalidReason | null {
  const { history, context } = input;
  const tuple = history.checkpointTupleFor(context.environmentId, context.manifestVersion);
  if (tuple !== undefined) {
    if (tuple.kind === "conflicting") {
      return "checkpoint-equivocation";
    }
    return tuple.epoch === context.epoch && tuple.manifestSigHashHex === signedBytesHashHex
      ? null
      : "checkpoint-binding-mismatch";
  }
  // strict: 宣言ヘッド時点の当該環境の現エポックとの厳密一致(削除・member
  // 未満への降格は全環境ローテーションを伴う — §7 — ため、write 資格を失った
  // 鍵では現エポックのマニフェストを署名できない)
  const atHead = history.environmentStateAt(context.environmentId, context.chainHeadSeq);
  if (atHead === undefined) {
    return "environment-not-created-at-head";
  }
  return atHead.currentEpoch === context.epoch ? null : "epoch-not-current-at-head";
}

/**
 * 8. チェックポイント整合の規則 1(§6.3 / §4.3 (4)): 当該環境の最新
 * `checkpoint` 基準に対する manifestVersion・epoch の非後退。基準を持たない
 * 環境は対象外(その環境の保証はエポック整合のみ — §6.3)。同版・異ハッシュの
 * 拒否は (4) の束縛が担う(最新基準の版のタプルは必ず存在するため)。
 */
function checkpointIntegrityReason(
  input: DistributedEnvManifestInput,
): ManifestInvalidReason | null {
  const baseline = input.history.latestCheckpointFor(input.context.environmentId);
  if (baseline === undefined) {
    return null;
  }
  if (
    input.context.manifestVersion < baseline.manifestVersion ||
    input.context.epoch < baseline.epoch
  ) {
    return "checkpoint-regressed";
  }
  return null;
}

async function contentReason(
  input: DistributedEnvManifestInput,
): Promise<ManifestInvalidReason | null> {
  const { context } = input;
  // 5. 環境メタ整合(AUTH_SPEC §12-5 (7)): マニフェストが束縛する環境メタ
  //    ステートメントの座標が、検証済みの最新形と一致すること
  if (
    context.envMetaVersion !== input.envMeta.metaVersion ||
    context.envMetaSigHashHex !== input.envMeta.sigHashHex
  ) {
    return "env-meta-mismatch";
  }
  // 6. ダイジェスト再計算(§4.3 (3)): 検証済みステートメント集合(tombstone
  //    込み)からの再計算一致。不一致はステートメントの欠落・注入・順序違反
  const digest = await computeVariablesDigest(context.suite, input.entries);
  if (!digest.ok) {
    // entries は検証済みステートメント由来であり、構造不正は呼び出し側のバグ。
    // ここでは形式不一致として同じ理由コードに畳む(秘密を含まない)
    return "variables-digest-mismatch";
  }
  return digest.value === context.variablesDigestHex ? null : "variables-digest-mismatch";
}

function prevReason(input: DistributedEnvManifestInput): ManifestInvalidReason | null {
  const { context, predecessor } = input;
  // prev の形(latest-only でも必ず検査): manifestVersion 1 = 空、> 1 = 64 hex。
  // 個別フィールドの hex 形式は manifestContextInvalidField が検査済みなので、
  // ここは manifestVersion との結合のみ
  if ((context.manifestVersion === 1) !== (context.prevManifestSigHashHex === "")) {
    return "prev-shape-mismatch";
  }
  if (predecessor === undefined) {
    return null;
  }
  // 7. 連鎖整合: prev の実在一致とエポック非減少(§4.1 単調性のマニフェスト版 —
  //    rotate 後に旧エポックを焼き込んだ前進 manifestVersion の検出)。
  //    prev 不一致を Ed25519 failure に潰さない(value-verify と同じ裁定)
  if (context.prevManifestSigHashHex !== predecessor.signedBytesHashHex) {
    return "prev-hash-mismatch";
  }
  if (context.epoch < predecessor.epoch) {
    return "epoch-regressed";
  }
  return null;
}

/**
 * Verifies one distributed (or submitted) environment manifest against a
 * verified chain history (CRYPTO_SPEC §4.3 / §6.3 / §6.4). Returns the
 * manifest's signed-bytes hash on success — the anchor for the next
 * manifestVersion's prev chain, for the local floor's manifest record and
 * for same-coordinate fork evidence (§14.2-5).
 *
 * The client passes the distributed issuer identity; the server passes the
 * calling principal's acceptance-time chain member identity (§12-5 (1): the
 * head-time key binding must then equal the acceptance-time key, which is
 * exactly the `issuer-key-mismatch-at-head` check).
 */
export async function verifyDistributedEnvManifest(
  input: DistributedEnvManifestInput,
): Promise<CryptoResult<{ readonly signedBytesHashHex: string }>> {
  const field =
    manifestContextInvalidField(input.context) ??
    distributedInputInvalidField({
      actorKeyFingerprintHex: input.issuerKeyFingerprintHex,
      actorKeyFingerprintField: "issuerKeyFingerprintHex",
      signatureHex: input.signatureHex,
      predecessorSignedBytesHashHex: input.predecessor?.signedBytesHashHex,
    });
  if (field !== null) {
    return invalidInput(field);
  }

  // 1. 鍵の選択(§6.3-1 前段。検査順は value-verify / meta-verify と同一)
  const imported = await importActorKeyByFingerprint({
    history: input.history,
    actorUserId: input.context.issuerUserId,
    actorKeyFingerprintHex: input.issuerKeyFingerprintHex,
    onUnknown: { kind: "EnvManifestInvalid", reason: "issuer-unknown" },
  });
  if (!imported.ok) {
    return imported;
  }
  const signature = await verifyEnvManifestSignature({
    context: input.context,
    signatureHex: input.signatureHex,
    issuerPublicKey: imported.value,
  });
  if (!signature.ok) {
    return signature;
  }

  // 2〜3. ヘッド束縛・認可時点(発行契機はすべて member 以上 — §4.3)
  const headReason = headAuthorizationReason({
    history: input.history,
    chainHeadSeq: input.context.chainHeadSeq,
    chainHeadHashHex: input.context.chainHeadHashHex,
    actorUserId: input.context.issuerUserId,
    actorKeyFingerprintHex: input.issuerKeyFingerprintHex,
    requiredRoleRank: ROLE_RANK.member,
    reasons: HEAD_AUTHORIZATION_REASONS,
  });
  if (headReason !== null) {
    return manifestInvalid(headReason);
  }
  // prev 連鎖は §4.3 (1) の一部(§6.3-6 と同型)であり、エポック整合 (2) に
  // 先行する(v1-nonempty-prev / v2-empty-prev の形検査が束縛判定より先に
  // 落ちることをベクターが固定する)
  const chainReason = prevReason(input);
  if (chainReason !== null) {
    return manifestInvalid(chainReason);
  }
  // チェックポイント束縛(2)の照合対象 = 自身の signed_bytes ハッシュ
  // (成功時の返り値と同一 — 束縛照合のために先に計算する)
  const signedBytesHashHex = encodeHex(await sha256(buildEnvManifestSignedBytes(input.context)));
  const epochReason = epochIntegrityReason(input, signedBytesHashHex);
  if (epochReason !== null) {
    return manifestInvalid(epochReason);
  }
  const digestReason = await contentReason(input);
  if (digestReason !== null) {
    return manifestInvalid(digestReason);
  }
  const checkpointReason = checkpointIntegrityReason(input);
  if (checkpointReason !== null) {
    return manifestInvalid(checkpointReason);
  }
  return { ok: true, value: { signedBytesHashHex } };
}
