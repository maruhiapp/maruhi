// メタステートメントのサーバー検証(AUTH_SPEC §12-5 のメタ規則 = CRYPTO_SPEC §4.2 / §6.4)。

import type {
  ChainHistoryIndex,
  ChainMember,
  MetaInvalidReason,
  MetaPredecessor,
  MetaStatementTarget,
} from "@maruhi/crypto";
import { verifyDistributedMetaStatement } from "@maruhi/crypto";
import { Effect } from "effect";

import type {
  DataRejectedError,
  MetaStatementInput,
  MetaStatementRejectReason,
} from "./data-plane.ts";
import { rejectData } from "./data-plane.ts";
import { DataStore } from "./data-store.ts";
import { MAX_VERSIONS_PER_VARIABLE } from "./policy.ts";
import { metaVersionsExceeded } from "./quotas.ts";

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
  // §4.2 レイアウト v2 の遷移・単調性理由(S1 — crypto 層の語彙追加に伴う網羅
  // 維持のみ)。ワイヤ v2(layoutVersion / スキーマ欄の Schema)は S2 で導入する
  // ため、現行サーバーの受理面では v2 の predecessor が存在せず到達しない
  "declared-after-active": "chain-head-state-mismatch",
  "layout-regression": "chain-head-state-mismatch",
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
    // InvalidInput / KeyImportFailed / UnsupportedMetaLayout は Schema 検証済み
    // ワイヤ + 検証済みチェーン由来の鍵では到達しない(実装バグ = defect。
    // エラー値に秘密は含まれない)。ただし UnsupportedMetaLayout は S2 でワイヤに
    // layoutVersion が乗ると「古いサーバー × 新しいクライアント」で実際に発生する
    // **正常系**になるため、S2 ではこの手前に「クライアント更新が必要」の typed
    // rejection への分岐を追加すること(裁定 CR — defect の 500 に落とすのは
    // 「改竄警告ではなく正直な update-required」の真逆。PR #116 レビュー対応)
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
export const ensureMetaCas = (
  latestMetaVersion: number,
  statement: MetaStatementInput,
): Effect.Effect<void, DataRejectedError> =>
  statement.metaVersion === latestMetaVersion + 1
    ? Effect.void
    : Effect.fail(
        rejectData({ kind: "meta-version-conflict", currentMetaVersion: latestMetaVersion }),
      );

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
export const acceptMetaStatement = (input: {
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
      // 保存済みステートメントは現行すべてレイアウト 1(ワイヤ v2 の受理 = S2)。
      // MetaPredecessor.layoutVersion は fail-closed の必須フィールドなので明示
      // する — S2 で layout_version 列を保存し、アンカーの実値をここへ通すこと
      predecessor: { ...anchor, layoutVersion: 1 },
    });
  });
