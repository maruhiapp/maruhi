// データプレーンの Effect プログラム(AUTH_SPEC §12)。
//
// 判定順(§12-3): チェーン導出メンバーシップ + role 下限(requireMemberState)→
// 環境・変数の存在 → 意味論的検査(ID / 名前の衝突、エポック・バージョンの CAS、
// DEK ラップの受信者検証)→ 数量ポリシー(§12-8)→ 書き込み + 監査イベント
// (AUDIT_SPEC §3.3)。
//
// 全プログラム(読み取り含む)は DO の Semaphore(1) permit 下で実行される前提:
// permit 外の読み取りは「メンバーシップ判定 → データ読み」の間に remove_member が
// 割り込む TOCTOU(削除直後のメンバーへの配布 — §11-2 違反)を作るため、読み取りも
// 直列化する(Bugbot 指摘 2026-08-02)。

import type {
  ChainHistoryIndex,
  ChainMember,
  ChainState,
  MetaInvalidReason,
  MetaPredecessor,
  MetaStatementTarget,
  ValueInvalidReason,
  ValuePredecessor,
} from "@maruhi/crypto";
import {
  decodeHex,
  importSigningPublicKey,
  verifyDekWrapSignature,
  verifyDistributedMetaStatement,
  verifyDistributedValue,
} from "@maruhi/crypto";
import { Effect } from "effect";

import type { AuditEventInput } from "./audit-store.ts";
import { AuditStore } from "./audit-store.ts";
import type { StateCache } from "./chain-store.ts";
import type {
  DataActor,
  DataRejectedError,
  DataRejection,
  DekWrapInput,
  DekWrapRefInput,
  EnvironmentPullValue,
  EnvironmentSummaryValue,
  MetaStatementInput,
  MetaStatementRejectReason,
  MetaStatementStatusInput,
  ValueInput,
  ValueSignatureRejectReason,
  VariableVersionValue,
} from "./data-plane.ts";
import { currentEpochOf, dataEvent, rejectData, requireMemberState } from "./data-plane.ts";
import type { DataWriteOps, VariableRow } from "./data-store.ts";
import { DataStore } from "./data-store.ts";
import {
  MAX_ACTIVE_ENVIRONMENTS,
  MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
  MAX_DEK_WRAPS_PER_REQUEST,
  MAX_ENVIRONMENT_ROWS,
  MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
  MAX_PROJECT_DEK_WRAP_ROWS,
  MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
  MAX_VERSIONS_PER_VARIABLE,
} from "./policy.ts";

// ---------------------------------------------------------------------------
// 共有ガード
// ---------------------------------------------------------------------------

/** 現存(非 tombstone)の環境。存在しなければ environment-not-found。 */
const requireActiveEnvironment = (environmentId: string) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const environment = yield* store.findEnvironment(environmentId);
    if (environment === null || environment.deletedAtMs !== null) {
      return yield* rejectData({ kind: "environment-not-found", environmentId });
    }
    return environment;
  });

const requireActiveVariable = (environmentId: string, variableId: string) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const variable = yield* store.findVariable(environmentId, variableId);
    if (variable === null || variable.deletedAtMs !== null) {
      return yield* rejectData({ kind: "variable-not-found", variableId });
    }
    return variable;
  });

/** 保存済みの値(epoch, version)に対する CAS(§12-5): 現エポック × 最新 + 1 のみ。 */
function checkValueCas(
  state: ChainState,
  environmentId: string,
  latestVersion: number,
  value: ValueInput,
): DataRejection | null {
  const currentEpoch = currentEpochOf(state, environmentId);
  if (value.epoch !== currentEpoch) {
    return { kind: "epoch-conflict", currentEpoch };
  }
  if (value.version !== latestVersion + 1) {
    return { kind: "version-conflict", currentVersion: latestVersion };
  }
  return null;
}

const ensureValueCas = (
  state: ChainState,
  environmentId: string,
  latestVersion: number,
  value: ValueInput,
): Effect.Effect<void, DataRejectedError> => {
  const rejection = checkValueCas(state, environmentId, latestVersion, value);
  return rejection === null ? Effect.void : Effect.fail(rejectData(rejection));
};

// ---------------------------------------------------------------------------
// 値署名のサーバー検証(§12-5 = CRYPTO_SPEC §4.1 / §6.4)
// ---------------------------------------------------------------------------

/**
 * crypto の詳細理由 → ワイヤの 3 理由(仮裁定 C)への写像。
 * chain-head-future はサーバーにとって「自チェーンに存在しない seq」なので
 * chain-head-unknown に畳む(クライアント側の再同期分岐はサーバーには無い)。
 * 網羅は Record 型が静的に強制する(理由コード追加時にコンパイルエラー)。
 */
const VALUE_REJECT_REASONS: Readonly<Record<ValueInvalidReason, ValueSignatureRejectReason>> = {
  "signature-invalid": "signature-invalid",
  "chain-head-mismatch": "chain-head-unknown",
  "chain-head-future": "chain-head-unknown",
  "writer-unknown": "chain-head-state-mismatch",
  "writer-not-member-at-head": "chain-head-state-mismatch",
  "writer-key-mismatch-at-head": "chain-head-state-mismatch",
  "writer-role-insufficient-at-head": "chain-head-state-mismatch",
  "environment-not-created-at-head": "chain-head-state-mismatch",
  "epoch-not-current-at-head": "chain-head-state-mismatch",
  "prev-shape-mismatch": "chain-head-state-mismatch",
  "prev-hash-mismatch": "chain-head-state-mismatch",
  "epoch-regressed": "chain-head-state-mismatch",
};

/**
 * 値署名の受理検証(§12-5 の 1〜5)。判定順は CAS(epoch / version)の後・数量
 * ポリシーの前(session-14 裁定 D)。検査内容:
 *
 * 1. 署名は呼び出し主体の受理時点チェーン導出 sig 鍵で検証し、writer_user_id にも
 *    呼び出し主体を用いる(他人が署名した値の持ち込み拒否)
 * 2. 宣言ヘッド(hash + seq)の exact pair が自チェーン上に存在する
 * 3. 宣言ヘッド時点でも member 以上で、当時の束縛鍵 = 受理時点の鍵
 *    (remove → 別鍵 re-add の旧在籍区間ヘッド宣言の拒否)
 * 4. 宣言ヘッド時点で環境作成済みかつ current epoch = 値 epoch
 * 5. version 1 は prev 空、version > 1 は保存済み N-1 の signed-bytes hash と一致
 *
 * 座標(project / environment / variable)はサーバー側の値(genesis ハッシュ・
 * URL / 保存先)から再構成する — クライアント申告の AAD から組まない(§12-5)。
 * 宣言ヘッドは現ヘッドと同一でなくてよく、seq 単調性・サーバー独自のエポック
 * 単調比較も課さない(裁定 D — 「現エポックのみ受理 + rotate +1 + version CAS」の
 * 帰結として構造的に単調)。
 *
 * 成功時はサーバー再計算の signed_bytes ハッシュを返す(保存行に書く)。
 * すべての crypto await はこの Effect 内で完了する(同期書き込みフェーズより前)。
 */
const ensureValueSignature = (input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly variableId: string;
  readonly history: ChainHistoryIndex;
  readonly member: ChainMember;
  readonly value: ValueInput;
}) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    // predecessor(version > 1): 保存済み N-1 の signed_bytes ハッシュ。CAS 通過後
    // なので必ず存在する(欠落はストレージ / 実装バグ = defect)。version 1 は
    // predecessor なし — prev 空の形検査は verifyDistributedValue が行う
    let predecessor: ValuePredecessor | undefined;
    if (input.value.version > 1) {
      const anchor = yield* store.versionAnchor(
        input.environmentId,
        input.variableId,
        input.value.version - 1,
      );
      if (anchor === null) {
        return yield* Effect.die(new Error("predecessor version row missing after CAS acceptance"));
      }
      predecessor = anchor;
    }
    const verified = yield* Effect.promise(() =>
      verifyDistributedValue({
        history: input.history,
        context: {
          suite: input.value.suite,
          projectId: input.projectId,
          environmentId: input.environmentId,
          epoch: input.value.epoch,
          variableId: input.variableId,
          version: input.value.version,
          nonceHex: input.value.nonceHex,
          ciphertextHex: input.value.ciphertextHex,
          prevValueSigHashHex: input.value.prevValueSigHashHex,
          // writer = 呼び出し主体(§12-5 の 1)。検証鍵と head 時点の束縛一致は
          // FP(受理時点のチェーン導出メンバー)で verifyDistributedValue が検査
          writerUserId: input.member.userId,
          chainHeadHashHex: input.value.chainHeadHashHex,
          chainHeadSeq: input.value.chainHeadSeq,
        },
        writerKeyFingerprintHex: input.member.keyFingerprintHex,
        signatureHex: input.value.signatureHex,
        predecessor,
      }),
    );
    if (verified.ok) {
      return verified.value.signedBytesHashHex;
    }
    if (verified.error.kind === "ValueInvalid") {
      return yield* rejectData({
        kind: "value-rejected",
        reason: VALUE_REJECT_REASONS[verified.error.reason],
      });
    }
    // InvalidInput / KeyImportFailed は Schema 検証済みワイヤ + 検証済みチェーン
    // 由来の鍵では到達しない(実装バグ = defect。エラー値に秘密は含まれない)
    return yield* Effect.die(new Error(`value verification failed: ${verified.error.kind}`));
  });

// ---------------------------------------------------------------------------
// メタステートメントのサーバー検証(§12-5 のメタ規則 = CRYPTO_SPEC §4.2 / §6.4)
// ---------------------------------------------------------------------------

/**
 * crypto の詳細理由 → ワイヤの 3 理由への写像(値署名の VALUE_REJECT_REASONS と
 * 同じ仮裁定 C の規約 — 語彙を共有し新理由コードを作らない。session-12 §6-7)。
 * 網羅は Record 型が静的に強制する。
 */
const META_REJECT_REASONS: Readonly<Record<MetaInvalidReason, MetaStatementRejectReason>> = {
  "signature-invalid": "signature-invalid",
  "chain-head-mismatch": "chain-head-unknown",
  "chain-head-future": "chain-head-unknown",
  "author-unknown": "chain-head-state-mismatch",
  "author-not-member-at-head": "chain-head-state-mismatch",
  "author-key-mismatch-at-head": "chain-head-state-mismatch",
  "author-role-insufficient-at-head": "chain-head-state-mismatch",
  "prev-shape-mismatch": "chain-head-state-mismatch",
  "prev-hash-mismatch": "chain-head-state-mismatch",
  "revived-after-delete": "chain-head-state-mismatch",
};

/**
 * メタステートメントの受理検証(§12-5 の 1〜3 + prev 連鎖)。検査内容:
 *
 * 1. 署名は呼び出し主体の受理時点チェーン導出 sig 鍵で検証し、author_user_id にも
 *    呼び出し主体を用いる(他人が署名したステートメントの持ち込み拒否)
 * 2. 宣言ヘッド(hash + seq)の exact pair が検証対象チェーン上に存在する
 * 3. 宣言ヘッド時点でも必要 role(環境の削除のみ admin、それ以外は member —
 *    §12-3 の二重判定)で、当時の束縛鍵 = 受理時点の鍵
 * 4. metaVersion 1 は prev 空、> 1 は保存済み直前ステートメントの signed-bytes
 *    hash と一致し、直前が deleted なら拒否(§4.2 — 再 active 化の禁止)
 *
 * エポック整合(値の §12-5 の 4)はメタに存在しない(エポックアンカーなし —
 * §4.2。環境の存在も検査しない — §12-4 の複合同梱形との両立)。
 * 座標(project / environment / variable)はサーバー側の値(genesis ハッシュ・
 * URL / 保存先)から再構成する — ワイヤの申告値から組まない(§12-5)。
 *
 * 成功時はサーバー再計算の signed_bytes ハッシュを返す(保存行に書く)。
 */
export const ensureMetaStatementSignature = (input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly target: MetaStatementTarget;
  readonly history: ChainHistoryIndex;
  readonly member: ChainMember;
  readonly statement: MetaStatementInput;
  /** metaVersion > 1 のとき保存済み直前ステートメントのアンカー(呼び出し側が引く)。 */
  readonly predecessor?: MetaPredecessor | undefined;
}) =>
  Effect.gen(function* () {
    const verified = yield* Effect.promise(() =>
      verifyDistributedMetaStatement({
        history: input.history,
        context: {
          suite: input.statement.suite,
          projectId: input.projectId,
          environmentId: input.environmentId,
          target: input.target,
          name: input.statement.name,
          status: input.statement.status,
          metaVersion: input.statement.metaVersion,
          prevMetaSigHashHex: input.statement.prevMetaSigHashHex,
          // author = 呼び出し主体(§12-5 の 1)。検証鍵と head 時点の束縛一致は
          // FP(受理時点のチェーン導出メンバー)で verifyDistributedMetaStatement が検査
          authorUserId: input.member.userId,
          chainHeadHashHex: input.statement.chainHeadHashHex,
          chainHeadSeq: input.statement.chainHeadSeq,
        },
        authorKeyFingerprintHex: input.member.keyFingerprintHex,
        signatureHex: input.statement.signatureHex,
        predecessor: input.predecessor,
      }),
    );
    if (verified.ok) {
      return verified.value.signedBytesHashHex;
    }
    if (verified.error.kind === "MetaStatementInvalid") {
      return yield* rejectData({
        kind: "meta-rejected",
        reason: META_REJECT_REASONS[verified.error.reason],
      });
    }
    // InvalidInput / KeyImportFailed は Schema 検証済みワイヤ + 検証済みチェーン
    // 由来の鍵では到達しない(実装バグ = defect。エラー値に秘密は含まれない)
    return yield* Effect.die(
      new Error(`meta statement verification failed: ${verified.error.kind}`),
    );
  });

/**
 * §12-1: name は NFC 正規形でなければ 422。サーバーは検査のみで正規化しない
 * (byte-exact 署名との両立 — 正規化の実施主体は署名前のクライアント)。
 */
export const ensureNfcName = (name: string): Effect.Effect<void, DataRejectedError> =>
  name.normalize("NFC") === name ? Effect.void : Effect.fail(rejectData({ kind: "name-not-nfc" }));

/** metaVersion の CAS(§12-5): 申告 == 最新 + 1 のみ。409 は最新番号のみを返す。 */
const ensureMetaCas = (
  latestMetaVersion: number,
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> =>
  statement.metaVersion === latestMetaVersion + 1
    ? Effect.void
    : Effect.fail(
        rejectData({ kind: "meta-version-conflict", currentMetaVersion: latestMetaVersion }),
      );

/**
 * metaVersion 行数の上限(仮裁定 — §12-8 の「バージョン数 / 変数」と同値を
 * ステートメント行にも適用。rename 連打による DO ストレージ肥大の遮断)。
 * 削除(status deleted)は対象外: tombstone は連鎖の終端で追加行は高々 1 行
 * であり、上限で削除まで遮断すると上限到達リソースがどの role でも恒久的に
 * 削除不能になる(§12-8 の「削除で解放される」原則との衝突 — レビュー②③)。
 * 判定は保存済み状態(latest + 1)基準: CAS 前の stale な申告 metaVersion を
 * limit-exceeded と誤報せず、実際に上限へ達したときのみ 422 にする。
 */
export function metaVersionsExceeded(
  latestMetaVersion: number,
  status: MetaStatementStatusInput,
): boolean {
  return status !== "deleted" && latestMetaVersion + 1 > MAX_VERSIONS_PER_VARIABLE;
}

const ensureMetaQuota = (
  latestMetaVersion: number,
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> =>
  metaVersionsExceeded(latestMetaVersion, statement.status)
    ? Effect.fail(
        rejectData({
          kind: "limit-exceeded",
          resource: "meta-versions",
          limit: MAX_VERSIONS_PER_VARIABLE,
        }),
      )
    : Effect.void;

/**
 * rename / 削除に共通するメタ受理列(§12-5): metaVersion 上限 → CAS(409 は
 * 最新番号のみ)→ 保存済み直前ステートメントのアンカー取得(CAS 通過後は必ず
 * 存在 — 欠落は defect)→ 署名検証(predecessor 込み — prev 連鎖と削除後の
 * 再ステートメント拒否)。成功時はサーバー再計算の signed_bytes ハッシュを返す。
 */
const acceptMetaStatement = (input: {
  readonly projectId: string;
  readonly environmentId: string;
  readonly target: MetaStatementTarget;
  readonly latestMetaVersion: number;
  readonly history: ChainHistoryIndex;
  readonly member: ChainMember;
  readonly statement: MetaStatementInput;
}) =>
  Effect.gen(function* () {
    yield* ensureMetaQuota(input.latestMetaVersion, input.statement);
    yield* ensureMetaCas(input.latestMetaVersion, input.statement);
    const store = yield* DataStore;
    const anchor =
      input.target.kind === "variable"
        ? yield* store.variableMetaAnchor(
            input.environmentId,
            input.target.variableId,
            input.latestMetaVersion,
          )
        : yield* store.environmentMetaAnchor(input.environmentId, input.latestMetaVersion);
    if (anchor === null) {
      return yield* Effect.die(new Error("meta predecessor row missing after CAS acceptance"));
    }
    return yield* ensureMetaStatementSignature({
      projectId: input.projectId,
      environmentId: input.environmentId,
      target: input.target,
      history: input.history,
      member: input.member,
      statement: input.statement,
      predecessor: anchor,
    });
  });

/** §12-8: 累積暗号文バイトの上限。追加分を含めて判定する純関数(ユニットテスト用に公開)。 */
export function projectBytesExceeded(storedBytes: number, addedBytes: number): boolean {
  return storedBytes + addedBytes > MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES;
}

const ensureProjectCapacity = (addedBytes: number) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const stored = yield* store.totalCiphertextBytes;
    if (projectBytesExceeded(stored, addedBytes)) {
      return yield* rejectData({
        kind: "limit-exceeded",
        resource: "project-ciphertext-bytes",
        limit: MAX_PROJECT_CIPHERTEXT_TOTAL_BYTES,
      });
    }
  });

/**
 * §12-8: プロジェクト累積の DEK ラップ行数上限。追加分を含めて判定する純関数
 * (上限行数の実生成は非現実的なため、判定はユニットテスト用に公開する —
 * chainCapacityExceeded / projectBytesExceeded と同じ形)。
 */
export function wrapRowsExceeded(storedRows: number, addedRows: number): boolean {
  return storedRows + addedRows > MAX_PROJECT_DEK_WRAP_ROWS;
}

/** ラップ挿入の全経路(DEK 登録・環境作成)で呼ぶ(§12-8)。 */
const ensureWrapRowCapacity = (addedRows: number) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const stored = yield* store.countWrapRows;
    if (wrapRowsExceeded(stored, addedRows)) {
      return yield* rejectData({
        kind: "limit-exceeded",
        resource: "dek-wrap-rows",
        limit: MAX_PROJECT_DEK_WRAP_ROWS,
      });
    }
  });

// ---------------------------------------------------------------------------
// DEK ラップの受理検証(§12-6 = CRYPTO_SPEC §6.3 ゴーストメンバー対策のサーバー側)
// ---------------------------------------------------------------------------

/** 1 ラップの検査(認知的複雑度の分割)。ok なら null。 */
function checkOneWrap(
  state: ChainState,
  currentEpoch: number,
  wrap: DekWrapInput,
  seen: Set<string>,
): DataRejection | null {
  if (wrap.epoch < 1 || wrap.epoch > currentEpoch) {
    return { kind: "dek-wrap-rejected", reason: "epoch-out-of-range" };
  }
  const member = state.members.get(wrap.recipientUserId);
  if (member === undefined) {
    return { kind: "dek-wrap-rejected", reason: "recipient-not-member" };
  }
  if (member.encPubHex !== wrap.recipientEncPubHex) {
    return { kind: "dek-wrap-rejected", reason: "recipient-key-mismatch" };
  }
  const key = `${wrap.epoch}:${wrap.recipientUserId}`;
  if (seen.has(key)) {
    return { kind: "dek-wrap-rejected", reason: "duplicate-recipient" };
  }
  seen.add(key);
  return null;
}

function checkWrapRecipients(
  state: ChainState,
  currentEpoch: number,
  wraps: readonly DekWrapInput[],
): DataRejection | null {
  if (wraps.length > MAX_DEK_WRAPS_PER_REQUEST) {
    return {
      kind: "limit-exceeded",
      resource: "dek-wraps-per-request",
      limit: MAX_DEK_WRAPS_PER_REQUEST,
    };
  }
  const seen = new Set<string>();
  for (const wrap of wraps) {
    const rejection = checkOneWrap(state, currentEpoch, wrap, seen);
    if (rejection !== null) {
      return rejection;
    }
  }
  return null;
}

/**
 * §12-6 / CRYPTO_SPEC §5.1: 全ラップの登録署名を検証する。署名者 = API 呼び出し
 * 主体の厳密一致が受理条件なので、検証鍵は呼び出し主体の**受理時点のチェーン
 * 導出 sig 公開鍵**(= 登録時点の鍵。全操作は permit 下で直列化されている)。
 * 他人が署名したラップの持ち込み(削除済みスロットへの第三者再投入を含む)は
 * ここで signature-invalid に落ちる。
 */
const ensureWrapSignatures = (
  projectId: string,
  environmentId: string,
  signer: ChainMember,
  wraps: readonly DekWrapInput[],
) =>
  Effect.gen(function* () {
    if (wraps.length === 0) {
      return;
    }
    // 検証済みチェーン由来の鍵はインポート可能が不変条件(失敗はストレージ /
    // 検証器のバグ = defect)。注: 後段のインポート成功は「WebCrypto の raw
    // Ed25519 インポートは長さ検査のみ」という現行ランタイム挙動にも依拠する
    // (add_member の対象メンバーの鍵はチェーン受理時にインポートされないため)。
    // ランタイムが点検証を導入した場合、不正な 32 バイト鍵を持つメンバー自身の
    // リクエストが defect になる(自傷のみ・攻撃には使えない)
    const signerKeyBytes = decodeHex(signer.sigPubHex);
    if (signerKeyBytes === null) {
      return yield* Effect.die(new Error("chain-derived signing key is not valid hex"));
    }
    const imported = yield* Effect.promise(() => importSigningPublicKey(signerKeyBytes));
    if (!imported.ok) {
      return yield* Effect.die(new Error("chain-derived signing key failed to import"));
    }
    for (const wrap of wraps) {
      const verified = yield* Effect.promise(() =>
        verifyDekWrapSignature({
          context: {
            suite: wrap.suite,
            projectId,
            environmentId,
            epoch: wrap.epoch,
            recipientUserId: wrap.recipientUserId,
            recipientEncPubHex: wrap.recipientEncPubHex,
            encHex: wrap.encHex,
            ciphertextHex: wrap.ciphertextHex,
            // 署名対象の署名者 = 呼び出し主体(§12-6)。鍵重複メンバーは
            // チェーン層(CRYPTO_SPEC §6.2)が禁止するが、仮に存在しても
            // 帰属付け替えはここで落ちる(§5.1 の独立防衛層)
            signerUserId: signer.userId,
          },
          signatureHex: wrap.signatureHex,
          signerPublicKey: imported.value,
        }),
      );
      if (!verified.ok) {
        // InvalidInput(構造不正)も含めて署名不受理に畳む(Schema 検証済みの
        // ワイヤでは実質 DekWrapSignatureInvalid のみ到達する)
        return yield* rejectData({ kind: "dek-wrap-rejected", reason: "signature-invalid" });
      }
    }
  });

/**
 * エポックごとの集合検査(§12-6): 初回登録(既存ラップなし)は現メンバー集合と
 * 完全一致(受信者検査済みなので個数一致 = 完全)、既存エポックへの追記は
 * 既存 (エポック, 受信者) との重複を拒否する。
 */
const checkWrapSets = (environmentId: string, state: ChainState, wraps: readonly DekWrapInput[]) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const epochs = [...new Set(wraps.map((wrap) => wrap.epoch))];
    for (const epoch of epochs) {
      const epochWraps = wraps.filter((wrap) => wrap.epoch === epoch);
      const existing = yield* store.countWrapsForEpoch(environmentId, epoch);
      if (existing === 0) {
        if (epochWraps.length !== state.members.size) {
          return yield* rejectData({ kind: "dek-wrap-rejected", reason: "recipient-missing" });
        }
        continue;
      }
      for (const wrap of epochWraps) {
        if (yield* store.wrapExists(environmentId, epoch, wrap.recipientUserId)) {
          return yield* rejectData({
            kind: "dek-wrap-exists",
            epoch,
            recipientUserId: wrap.recipientUserId,
          });
        }
      }
    }
  });

/**
 * ラップ集合の受理検証(§12-6)+ 数量ポリシー(§12-8)+ 登録署名の検証
 * (CRYPTO_SPEC §5.1)。挿入は呼び出し側の同期書き込みフェーズで行う。
 * ラップ挿入の全経路 — 独立登録 API(バックフィル・修復再登録)と複合リクエスト
 * (環境作成・ローテーション — composite-programs.ts)— がここを通るため、
 * 累積行数上限と署名必須の結線はこの 1 箇所でよい。署名検証(Ed25519 × 件数)は
 * 最も高価なため、安価な検査(件数・受信者・重複・集合)がすべて通った後に行う。
 */
export const ensureWrapSetAcceptable = (
  projectId: string,
  environmentId: string,
  state: ChainState,
  signer: ChainMember,
  currentEpoch: number,
  wraps: readonly DekWrapInput[],
) =>
  Effect.gen(function* () {
    const rejection = checkWrapRecipients(state, currentEpoch, wraps);
    if (rejection !== null) {
      return yield* rejectData(rejection);
    }
    yield* ensureWrapRowCapacity(wraps.length);
    yield* checkWrapSets(environmentId, state, wraps);
    yield* ensureWrapSignatures(projectId, environmentId, signer, wraps);
  });

/**
 * dek.registered(AUDIT_SPEC §3.3): 1 受信者 1 行(§5.1 の列構造 = 1 行 1
 * target)。受信者は target_user_id に載せ、(target_user_id, seq) の索引で
 * 「この受信者宛のラップの登録履歴」をそのまま引けるようにする。
 * actor_key_fingerprint には登録署名の署名者 FP を写す(§3.3 — セッション 07
 * 裁定 B「E の署名者 FP を写して突合可能にする」)。
 */
export function dekRegisteredEvent(
  actor: DataActor,
  signer: ChainMember,
  nowMs: number,
  environmentId: string,
  wrap: DekWrapInput,
): AuditEventInput {
  return dataEvent(actor, nowMs, "dek.registered", {
    environmentId,
    epoch: wrap.epoch,
    targetUserId: wrap.recipientUserId,
    actorKeyFingerprintHex: signer.keyFingerprintHex,
  });
}

// ---------------------------------------------------------------------------
// 環境管理(§12-4)。作成・ローテーションは複合リクエスト(composite-programs.ts)
// ---------------------------------------------------------------------------

/** 環境数の数量ポリシー(§12-8。複合作成 — composite-programs.ts — から呼ぶ)。 */
export const ensureEnvironmentQuota = Effect.gen(function* () {
  const store = yield* DataStore;
  const counts = yield* store.countEnvironments;
  if (counts.active + 1 > MAX_ACTIVE_ENVIRONMENTS) {
    return yield* rejectData({
      kind: "limit-exceeded",
      resource: "environments",
      limit: MAX_ACTIVE_ENVIRONMENTS,
    });
  }
  if (counts.rows + 1 > MAX_ENVIRONMENT_ROWS) {
    return yield* rejectData({
      kind: "limit-exceeded",
      resource: "environment-rows",
      limit: MAX_ENVIRONMENT_ROWS,
    });
  }
});

export const renameEnvironmentProgram = (
  actor: DataActor,
  environmentId: string,
  statement: MetaStatementInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { history, member, projectId } = yield* requireMemberState(actor.userId, "member", cache);
    const environment = yield* requireActiveEnvironment(environmentId);
    yield* ensureNfcName(statement.name);
    const store = yield* DataStore;
    if (yield* store.environmentNameTaken(statement.name, environmentId)) {
      return yield* rejectData({
        kind: "environment-conflict",
        environmentId,
        reason: "duplicate-name",
      });
    }
    // 判定順(値の裁定 D と同型): 上限 → CAS → ステートメント署名 → 原子書き込み
    const signedBytesHashHex = yield* acceptMetaStatement({
      projectId,
      environmentId,
      target: { kind: "environment" },
      latestMetaVersion: environment.latestMetaVersion,
      history,
      member,
      statement,
    });
    const audit = yield* AuditStore;
    const now = Date.now();
    yield* Effect.sync(() => {
      store.write.insertEnvironmentMetaStatement(
        environmentId,
        statement,
        signedBytesHashHex,
        { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
        now,
      );
      audit.appendSync(
        dataEvent(actor, now, "env.renamed", {
          environmentId,
          payload: { name: statement.name },
          actorKeyFingerprintHex: member.keyFingerprintHex,
        }),
      );
    });
  });

export const deleteEnvironmentProgram = (
  actor: DataActor,
  environmentId: string,
  statement: MetaStatementInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    // 受理時点 admin(§12-3)。宣言ヘッド時点 admin は署名検証(§12-3 の
    // 二重判定 — env × deleted の必要 role)が検査する
    const { history, member, projectId } = yield* requireMemberState(actor.userId, "admin", cache);
    const environment = yield* requireActiveEnvironment(environmentId);
    // deleted の name は直前 active 名を保持する(§4.2 — byte-exact)
    if (statement.name !== environment.name) {
      return yield* rejectData({ kind: "payload-mismatch", field: "name" });
    }
    const signedBytesHashHex = yield* acceptMetaStatement({
      projectId,
      environmentId,
      target: { kind: "environment" },
      latestMetaVersion: environment.latestMetaVersion,
      history,
      member,
      statement,
    });
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = Date.now();
    const variables = yield* store.listActiveVariables(environmentId);
    // 書き込みフェーズ(単一タスク): tombstone + データ削除 + deleted ステート
    // メント行と、存在区間を閉じる変数ごとの var.deleted(§12-4)+ env.deleted を
    // 原子的に書く。カスケード削除される変数は個別のステートメントを持たない
    // ため、var.deleted の FP は環境削除ステートメントの author FP を写す
    // (「FP = 署名の証跡」の意味論 — この削除を認可した署名は env 側にある)
    yield* Effect.sync(() => {
      store.write.retireEnvironment(environmentId, now);
      store.write.insertEnvironmentMetaStatement(
        environmentId,
        statement,
        signedBytesHashHex,
        { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
        now,
      );
      for (const variable of variables) {
        audit.appendSync(
          dataEvent(actor, now, "var.deleted", {
            environmentId,
            variableId: variable.variableId,
            actorKeyFingerprintHex: member.keyFingerprintHex,
          }),
        );
      }
      audit.appendSync(
        dataEvent(actor, now, "env.deleted", {
          environmentId,
          payload: { name: environment.name },
          actorKeyFingerprintHex: member.keyFingerprintHex,
        }),
      );
    });
  });

export const listEnvironmentsProgram = (actor: DataActor, cache: StateCache) =>
  Effect.gen(function* () {
    const { state } = yield* requireMemberState(actor.userId, "reader", cache);
    const store = yield* DataStore;
    const environments = yield* store.listEnvironmentStatements;
    // 削除済み環境もチェーン上に create_environment を持つ(チェーンは削除を
    // 観測しない — §6.2)ため、currentEpochOf は全行で導出可能
    return environments.map(
      (environment): EnvironmentSummaryValue => ({
        environmentId: environment.environmentId,
        currentEpoch: currentEpochOf(state, environment.environmentId),
        statement: environment.statement,
      }),
    );
  });

// ---------------------------------------------------------------------------
// 変数とバージョニング(§12-5)
// ---------------------------------------------------------------------------

function variableIdUnavailable(
  existing: VariableRow | null,
  variableId: string,
): DataRejection | null {
  if (existing === null) {
    return null;
  }
  const reason = existing.deletedAtMs === null ? "exists" : "retired";
  return { kind: "variable-conflict", variableId, reason };
}

const ensureVariableQuota = (environmentId: string) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const counts = yield* store.countVariables(environmentId);
    if (counts.active + 1 > MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT) {
      return yield* rejectData({
        kind: "limit-exceeded",
        resource: "variables",
        limit: MAX_ACTIVE_VARIABLES_PER_ENVIRONMENT,
      });
    }
    if (counts.rows + 1 > MAX_VARIABLE_ROWS_PER_ENVIRONMENT) {
      return yield* rejectData({
        kind: "limit-exceeded",
        resource: "variable-rows",
        limit: MAX_VARIABLE_ROWS_PER_ENVIRONMENT,
      });
    }
  });

/**
 * バージョン行の書き込み + var.version_pushed の記録(create / push 共通の末尾)。
 * 同期関数: 呼び出し側の書き込みフェーズ(単一の Effect.sync)内で使う。
 * writer は受理時点のチェーン導出メンバー(値署名の検証に使った鍵の持ち主 —
 * CRYPTO_SPEC §4.1)。監査は chain-derived writer FP のみを写す(AUDIT_SPEC §3.3 —
 * 署名・signed bytes・hash・nonce・暗号文は監査に載せない)。
 */
function writeVersionWithAudit(
  write: DataWriteOps,
  appendAudit: (event: AuditEventInput) => void,
  actor: DataActor,
  writer: ChainMember,
  environmentId: string,
  variableId: string,
  value: ValueInput,
  signedBytesHashHex: string,
  nowMs: number,
): void {
  write.insertVersion(
    environmentId,
    variableId,
    value,
    value.ciphertextHex.length / 2,
    signedBytesHashHex,
    { userId: writer.userId, keyFingerprintHex: writer.keyFingerprintHex },
    nowMs,
  );
  appendAudit(
    dataEvent(actor, nowMs, "var.version_pushed", {
      environmentId,
      variableId,
      epoch: value.epoch,
      version: value.version,
      actorKeyFingerprintHex: writer.keyFingerprintHex,
    }),
  );
}

export const createVariableProgram = (
  actor: DataActor,
  environmentId: string,
  input: {
    readonly variableId: string;
    readonly statement: MetaStatementInput;
    readonly value: ValueInput;
  },
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { state, history, member, projectId } = yield* requireMemberState(
      actor.userId,
      "member",
      cache,
    );
    yield* requireActiveEnvironment(environmentId);
    const store = yield* DataStore;
    const existing = yield* store.findVariable(environmentId, input.variableId);
    const unavailable = variableIdUnavailable(existing, input.variableId);
    if (unavailable !== null) {
      return yield* rejectData(unavailable);
    }
    yield* ensureVariableQuota(environmentId);
    yield* ensureNfcName(input.statement.name);
    if (yield* store.variableNameTaken(environmentId, input.statement.name, null)) {
      return yield* rejectData({
        kind: "variable-conflict",
        variableId: input.variableId,
        reason: "duplicate-name",
      });
    }
    // 作成 = version 1 の値 + metaVersion 1 のステートメントの同梱(§12-5)。
    // ワイヤ Schema が metaVersion 1・active・prev 空を固定するが、CAS は
    // 防衛線として残す(latest = 0 相当)
    yield* ensureMetaCas(0, input.statement);
    yield* ensureValueCas(state, environmentId, 0, input.value);
    // 同梱 version 1 の値・同梱ステートメントとも通常経路と同一の署名検証を
    // 受ける(§12-5 — 作成経由の検証迂回は値・メタとも不可)。判定順:
    // CAS → メタ署名 → 値署名 → 数量ポリシー(裁定 D への挿入)
    const metaSignedBytesHashHex = yield* ensureMetaStatementSignature({
      projectId,
      environmentId,
      target: { kind: "variable", variableId: input.variableId },
      history,
      member,
      statement: input.statement,
    });
    const signedBytesHashHex = yield* ensureValueSignature({
      projectId,
      environmentId,
      variableId: input.variableId,
      history,
      member,
      value: input.value,
    });
    yield* ensureProjectCapacity(input.value.ciphertextHex.length / 2);
    const audit = yield* AuditStore;
    const now = Date.now();
    // 書き込みフェーズ(単一タスク): 変数行 + ステートメント行 + version 1 +
    // 監査 2 行を原子的に書く(「latest_version = 0 のまま ID だけ占有された
    // 変数」を残さない)
    yield* Effect.sync(() => {
      store.write.insertVariable(environmentId, input.variableId, input.statement.name, now);
      store.write.insertVariableMetaStatement(
        environmentId,
        input.variableId,
        input.statement,
        metaSignedBytesHashHex,
        { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
        now,
      );
      // var.created の FP = 同梱 v1 の writer FP = author FP(同一主体 — §12-5。
      // テストが固定する)
      audit.appendSync(
        dataEvent(actor, now, "var.created", {
          environmentId,
          variableId: input.variableId,
          payload: { name: input.statement.name },
          actorKeyFingerprintHex: member.keyFingerprintHex,
        }),
      );
      writeVersionWithAudit(
        store.write,
        audit.appendSync,
        actor,
        member,
        environmentId,
        input.variableId,
        input.value,
        signedBytesHashHex,
        now,
      );
    });
    return {
      variableId: input.variableId,
      version: input.value.version,
      epoch: input.value.epoch,
    } satisfies VariableVersionValue;
  });

export const pushVersionProgram = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  value: ValueInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { state, history, member, projectId } = yield* requireMemberState(
      actor.userId,
      "member",
      cache,
    );
    yield* requireActiveEnvironment(environmentId);
    const variable = yield* requireActiveVariable(environmentId, variableId);
    yield* ensureValueCas(state, environmentId, variable.latestVersion, value);
    // 判定順(裁定 D): epoch / version CAS → 値署名(署名 → 宣言 head →
    // head 時点状態 → predecessor)→ 数量ポリシー → 原子書き込み。
    // 不受理時は variable / version / latest / audit のいずれも変更しない
    const signedBytesHashHex = yield* ensureValueSignature({
      projectId,
      environmentId,
      variableId,
      history,
      member,
      value,
    });
    if (value.version > MAX_VERSIONS_PER_VARIABLE) {
      return yield* rejectData({
        kind: "limit-exceeded",
        resource: "versions",
        limit: MAX_VERSIONS_PER_VARIABLE,
      });
    }
    yield* ensureProjectCapacity(value.ciphertextHex.length / 2);
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = Date.now();
    yield* Effect.sync(() => {
      writeVersionWithAudit(
        store.write,
        audit.appendSync,
        actor,
        member,
        environmentId,
        variableId,
        value,
        signedBytesHashHex,
        now,
      );
    });
    return {
      variableId,
      version: value.version,
      epoch: value.epoch,
    } satisfies VariableVersionValue;
  });

export const renameVariableProgram = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  statement: MetaStatementInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { history, member, projectId } = yield* requireMemberState(actor.userId, "member", cache);
    yield* requireActiveEnvironment(environmentId);
    const variable = yield* requireActiveVariable(environmentId, variableId);
    yield* ensureNfcName(statement.name);
    const store = yield* DataStore;
    if (yield* store.variableNameTaken(environmentId, statement.name, variableId)) {
      return yield* rejectData({ kind: "variable-conflict", variableId, reason: "duplicate-name" });
    }
    const signedBytesHashHex = yield* acceptMetaStatement({
      projectId,
      environmentId,
      target: { kind: "variable", variableId },
      latestMetaVersion: variable.latestMetaVersion,
      history,
      member,
      statement,
    });
    const audit = yield* AuditStore;
    const now = Date.now();
    yield* Effect.sync(() => {
      store.write.insertVariableMetaStatement(
        environmentId,
        variableId,
        statement,
        signedBytesHashHex,
        { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
        now,
      );
      audit.appendSync(
        dataEvent(actor, now, "var.renamed", {
          environmentId,
          variableId,
          payload: { name: statement.name },
          actorKeyFingerprintHex: member.keyFingerprintHex,
        }),
      );
    });
  });

export const deleteVariableProgram = (
  actor: DataActor,
  environmentId: string,
  variableId: string,
  statement: MetaStatementInput,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { history, member, projectId } = yield* requireMemberState(actor.userId, "member", cache);
    yield* requireActiveEnvironment(environmentId);
    const variable = yield* requireActiveVariable(environmentId, variableId);
    // deleted の name は直前 active 名を保持する(§4.2 — byte-exact)
    if (statement.name !== variable.name) {
      return yield* rejectData({ kind: "payload-mismatch", field: "name" });
    }
    const signedBytesHashHex = yield* acceptMetaStatement({
      projectId,
      environmentId,
      target: { kind: "variable", variableId },
      latestMetaVersion: variable.latestMetaVersion,
      history,
      member,
      statement,
    });
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = Date.now();
    // 書き込みフェーズ: tombstone + 全バージョン削除 + deleted ステートメント行
    // (保存・配布し続ける — §12-5)+ var.deleted(author FP — AUDIT_SPEC §3.3)
    yield* Effect.sync(() => {
      store.write.retireVariable(environmentId, variableId, now);
      store.write.insertVariableMetaStatement(
        environmentId,
        variableId,
        statement,
        signedBytesHashHex,
        { userId: member.userId, keyFingerprintHex: member.keyFingerprintHex },
        now,
      );
      audit.appendSync(
        dataEvent(actor, now, "var.deleted", {
          environmentId,
          variableId,
          actorKeyFingerprintHex: member.keyFingerprintHex,
        }),
      );
    });
  });

// ---------------------------------------------------------------------------
// 一括 pull(§12-7)と DEK 配布(§12-6)
// ---------------------------------------------------------------------------

export const pullEnvironmentProgram = (
  actor: DataActor,
  environmentId: string,
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { state } = yield* requireMemberState(actor.userId, "reader", cache);
    yield* requireActiveEnvironment(environmentId);
    const store = yield* DataStore;
    // 環境自身の最新ステートメント(§12-7 の検証材料の同梱)。環境行はステート
    // メントと原子的に作られる(複合受理)ため、欠落は不変条件違反 = defect
    const statement = yield* store.environmentStatement(environmentId);
    if (statement === null) {
      return yield* Effect.die(new Error("environment meta statement row missing"));
    }
    const variables = yield* store.latestVersions(environmentId);
    // 削除済み変数の deleted ステートメントも配布し続ける(§12-5 — 削除の
    // 否認・無断復活の検出材料。暗号文は削除済みなので値は伴わない)
    const deletedVariables = yield* store.deletedVariableStatements(environmentId);
    const deks = yield* store.listWrapsForRecipient(environmentId, actor.userId);
    // 監査(AUDIT_SPEC §3.3): 一括 pull は返した変数ごとに var.read を 1 行
    // (返した行に対して記録するため、行とイベントは常に一致する)
    const audit = yield* AuditStore;
    const now = Date.now();
    yield* Effect.sync(() => {
      for (const variable of variables) {
        audit.appendSync(
          dataEvent(actor, now, "var.read", {
            environmentId,
            variableId: variable.variableId,
            epoch: variable.epoch,
            version: variable.version,
          }),
        );
      }
    });
    return {
      environmentId,
      currentEpoch: currentEpochOf(state, environmentId),
      statement,
      variables,
      deletedVariables,
      deks,
    } satisfies EnvironmentPullValue;
  });

export const registerDekWrapsProgram = (
  actor: DataActor,
  environmentId: string,
  wraps: readonly DekWrapInput[],
  cache: StateCache,
) =>
  Effect.gen(function* () {
    const { state, member, projectId } = yield* requireMemberState(actor.userId, "member", cache);
    yield* requireActiveEnvironment(environmentId);
    const currentEpoch = currentEpochOf(state, environmentId);
    yield* ensureWrapSetAcceptable(projectId, environmentId, state, member, currentEpoch, wraps);
    const store = yield* DataStore;
    const audit = yield* AuditStore;
    const now = Date.now();
    yield* Effect.sync(() => {
      for (const wrap of wraps) {
        store.write.insertWrap(environmentId, wrap, member, now);
        audit.appendSync(dekRegisteredEvent(actor, member, now, environmentId, wrap));
      }
    });
  });

/**
 * §12-6 の修復経路: admin による (環境, エポック, 受信者) 単位のラップ削除。
 * 上書き禁止(可用性攻撃の遮断)は維持したまま、毒ラップを削除 → 不足分の
 * 追記経路で再登録する。存在しないタプルは 404(黙って成功させない)。
 */
export const deleteDekWrapsProgram = (
  actor: DataActor,
  environmentId: string,
  refs: readonly DekWrapRefInput[],
  cache: StateCache,
) =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "admin", cache);
    yield* requireActiveEnvironment(environmentId);
    if (refs.length > MAX_DEK_WRAPS_PER_REQUEST) {
      return yield* rejectData({
        kind: "limit-exceeded",
        resource: "dek-wraps-per-request",
        limit: MAX_DEK_WRAPS_PER_REQUEST,
      });
    }
    const store = yield* DataStore;
    const seen = new Set<string>();
    for (const ref of refs) {
      const key = `${ref.epoch}:${ref.recipientUserId}`;
      if (seen.has(key)) {
        return yield* rejectData({ kind: "dek-wrap-rejected", reason: "duplicate-recipient" });
      }
      seen.add(key);
      if (!(yield* store.wrapExists(environmentId, ref.epoch, ref.recipientUserId))) {
        return yield* rejectData({
          kind: "dek-wrap-not-found",
          epoch: ref.epoch,
          recipientUserId: ref.recipientUserId,
        });
      }
    }
    const audit = yield* AuditStore;
    const now = Date.now();
    // 書き込みフェーズ(単一タスク): 削除と dek.deleted(1 受信者 1 行 —
    // AUDIT_SPEC §3.3)を原子的に書く
    yield* Effect.sync(() => {
      for (const ref of refs) {
        store.write.deleteWrap(environmentId, ref.epoch, ref.recipientUserId);
        audit.appendSync(
          dataEvent(actor, now, "dek.deleted", {
            environmentId,
            epoch: ref.epoch,
            targetUserId: ref.recipientUserId,
          }),
        );
      }
    });
  });

export const listMyDekWrapsProgram = (actor: DataActor, environmentId: string, cache: StateCache) =>
  Effect.gen(function* () {
    yield* requireMemberState(actor.userId, "reader", cache);
    yield* requireActiveEnvironment(environmentId);
    const store = yield* DataStore;
    return yield* store.listWrapsForRecipient(environmentId, actor.userId);
  });
