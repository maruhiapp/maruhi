// チェックポイント整合のクライアント規則 2(CRYPTO_SPEC §6.3 — 値の非後退)。
//
// 環境ごとの基準は、検証済みチェーン上で**その環境のエントリを含む最新の
// `checkpoint`**(history.latestCheckpointFor — サーバー非依存のチェーン導出)。
// 値付き応答(一括 pull §12-7 / lease §14-2)に同梱される「チェックポイント時点の
// 値スナップショット列挙」に対して検査する:
//
//   1. **基準あり + 列挙なし = 拒否(MUST)** — 列挙の省略を「規則 2 のスキップ」に
//      落とさせない(基準の有無は検証済みチェーンからサーバー非依存に判定できる)
//   2. ワイヤの対応 checkpoint seq / hash は **advisory locator**(session-36
//      裁定 S — 検証の基準は常にチェーン導出)。§6.3-2 のヘッド束縛と同型の
//      2 分類: 申告 seq > 自ヘッド = 自チェーンが古いだけの可能性(future —
//      pull は有界再同期、lease は同一応答にチェーンが同梱されるため自己矛盾 =
//      即時拒否)/ 申告 seq ≤ 自ヘッド = 基準は確定済みで、不一致は硬い証拠
//   3. 列挙の再計算ダイジェスト(computeEnvValuesDigest — ベクター固定済みの
//      正規形)が基準の values_digest と一致すること
//   4. 配布された各変数: version がスナップショット以上・等号なら
//      value_signed_bytes ハッシュ一致・スナップショットより新しい version の
//      epoch は基準 epoch 以上(床規則 (c) のチェックポイント版 — 床を持たない
//      クライアントへの前進注入検出はこれが担う)
//   5. スナップショットに存在して配布に存在しない変数は、検証済み tombstone
//      (マニフェスト整合込み — 呼び出し側はマニフェスト段の後に本検査を置く)で
//      削除が説明されない限り欠落として拒否
//   6. スナップショットに存在しない配布変数はチェックポイント後の正当な作成で
//      ありうる(エポック基準 — 床規則 (c) の「version 0 相当」と同型。
//      マニフェスト整合は前段のダイジェスト再計算が担保済み)
//
// 基準を持たない環境は本検証の対象外(保証は床・マニフェストのエポック整合のみ —
// §6.3)。床を持たないクライアント(ワークロード — §9.1)の「基準なし警告」
// (SHOULD)は lease 経路の呼び出し側が担う(session-36 裁定 V)。
//
// 検査対象の variables / tombstones は §6.3 の署名検証を全通過したデータ、基準は
// 検証済みチェーンの導出値なので、ここでの不一致は正規署名済みデータとチェーン
// 公証の矛盾 = サーバーの巻き戻し・前進注入・改竄の証拠であり全件拒否する
// (呼び出し側は evidence として型付けする — errors.ts)。

import type { CheckpointValueSnapshot } from "@maruhi/api-schema";
import type { ChainHistoryIndex, EnvironmentCheckpointState } from "@maruhi/crypto";
import { computeEnvValuesDigest, SUITE_ID } from "@maruhi/crypto";

import { displayText } from "./display.ts";

/** 配布値のうち規則 2 が見る座標(values.ts の VerifiedPulledValue が満たす)。 */
export interface CheckpointCheckedValue {
  readonly variableId: string;
  readonly version: number;
  readonly epoch: number;
  /** 自計算の value_signed_bytes ハッシュ(§4.1 — 申告値ではない)。 */
  readonly signedBytesHashHex: string;
}

/**
 * 規則 2 の判定結果(future = §6.3-2b と同型の「自チェーンが古いだけの可能性」)。
 * rejected の evidence は「検証済みデータとチェーン公証の矛盾 = 再実行では
 * 解消しない証拠」かの型付け(false = 応答の取得ビューより後に基準が前進した
 * 良性競合でも説明できる形 — 再 pull で解消しうるため、rotate の巡末分類が
 * 証拠中断へ格上げしない。PR #100 Bugbot 指摘)。
 */
export type CheckpointIntegrityOutcome =
  | { readonly kind: "ok" }
  | { readonly kind: "future" }
  | { readonly kind: "rejected"; readonly message: string; readonly evidence: boolean };

function rejected(message: string): CheckpointIntegrityOutcome {
  return { kind: "rejected", message, evidence: true };
}

function retriable(message: string): CheckpointIntegrityOutcome {
  return { kind: "rejected", message, evidence: false };
}

/**
 * locator(申告 checkpoint 位置)の分類(裁定 S — §6.3-2 と同型)。null =
 * 位置は基準と一致(検査続行)。
 *
 * 有界再同期は**応答を取得し直さず**同じ本文を前進後のビューで再検証する
 * (values.ts の pullWithBoundedResync)ため、「基準」は応答の取得後に前進して
 * いることがある。応答の取得ビュー(fetchedAtHeadSeq)より後に基準が着地した
 * 形は、正直なサーバーの応答でも起きる(取得と再同期の窓に別の checkpoint が
 * 挟まる)— この形だけは evidence にせず retriable として拒否する(再 pull が
 * 新基準の列挙を持ってくる)。基準が取得ビュー以前から存在する形に良性の説明は
 * ない: サーバーは checkpoint 受理と原子的にスナップショットを保存する(§16-2)
 * ため、その応答が古い位置を主張するのは stale 配布・偽装の証拠。
 */
function locatorOutcome(
  history: ChainHistoryIndex,
  environmentId: string,
  snapshot: CheckpointValueSnapshot,
  baseline: EnvironmentCheckpointState | undefined,
  fetchedAtHeadSeq: number,
): CheckpointIntegrityOutcome | null {
  if (snapshot.chainSeq > history.headSeq) {
    // 応答生成の直前に checkpoint が着地した可能性(自チェーンが古いだけ)。
    // pull は有界再同期で解決し、lease は呼び出し側が自己矛盾として拒否する
    return { kind: "future" };
  }
  if (history.entryHashAt(snapshot.chainSeq) !== snapshot.entryHashHex) {
    return rejected(
      `The served checkpoint value snapshot declares an entry hash for seq ${snapshot.chainSeq} that does not match the verified chain (evidence of chain divergence or forgery)`,
    );
  }
  if (baseline === undefined) {
    // 位置は実在エントリだが、チェーン導出上そのエントリは当該環境を覆う
    // checkpoint ではない(覆っていれば基準が導出されている)= 偽装
    return rejected(
      `A checkpoint value snapshot claiming checkpoint seq ${snapshot.chainSeq} was served for environment ${displayText(environmentId)}, but the verified chain derives no checkpoint covering this environment (the response contradicts the chain)`,
    );
  }
  if (snapshot.chainSeq === baseline.seq) {
    return null;
  }
  if (snapshot.chainSeq < baseline.seq && baseline.seq > fetchedAtHeadSeq) {
    return retriable(
      `The served checkpoint value snapshot corresponds to checkpoint seq ${snapshot.chainSeq}, but a newer checkpoint covering environment ${displayText(environmentId)} (seq ${baseline.seq}) was accepted after this response's view. The response may simply predate it — retry the pull; if this persists, the server is serving stale snapshots`,
    );
  }
  return rejected(
    `The served checkpoint value snapshot claims checkpoint seq ${snapshot.chainSeq}, but the latest checkpoint covering environment ${displayText(environmentId)} on the verified chain is seq ${baseline.seq}, which the server had already stored when this response was generated (a stale or fabricated snapshot)`,
  );
}

/** 配布 1 変数 × スナップショット・基準の per-variable 検査(§6.3 規則 2)。 */
function servedValueReason(
  value: CheckpointCheckedValue,
  entry: { readonly version: number; readonly valueSigHashHex: string } | undefined,
  baseline: EnvironmentCheckpointState,
): string | null {
  if (entry === undefined) {
    // チェックポイント後の正当な作成でありうる — エポック基準(version 0 相当)
    return value.epoch < baseline.epoch
      ? `Variable ${displayText(value.variableId)} is not in the checkpoint snapshot but was served with epoch ${value.epoch}, below the checkpoint baseline epoch ${baseline.epoch} (evidence of a backdated creation with an old epoch key)`
      : null;
  }
  if (value.version < entry.version) {
    return `Variable ${displayText(value.variableId)} was served at version ${value.version}, below the version ${entry.version} notarized by checkpoint seq ${baseline.seq} (a value rollback below the checkpointed state)`;
  }
  if (value.version === entry.version && value.signedBytesHashHex !== entry.valueSigHashHex) {
    return `Variable ${displayText(value.variableId)} was served with signed bytes differing from the checkpointed hash for the same version ${value.version} (evidence of equivocation against the checkpointed state)`;
  }
  if (value.version > entry.version && value.epoch < baseline.epoch) {
    return `Variable ${displayText(value.variableId)} advanced beyond the checkpointed version but carries epoch ${value.epoch}, below the checkpoint baseline epoch ${baseline.epoch} (evidence of forward injection with an old epoch key)`;
  }
  return null;
}

/** スナップショットにあって配布にない変数の欠落検査(tombstone による説明のみ許容)。 */
function omissionReason(
  snapshot: CheckpointValueSnapshot,
  servedIds: ReadonlySet<string>,
  tombstoneIds: ReadonlySet<string>,
  baselineSeq: number,
): string | null {
  for (const entry of snapshot.values) {
    if (!servedIds.has(entry.variableId) && !tombstoneIds.has(entry.variableId)) {
      return `Variable ${displayText(entry.variableId)} exists in the checkpoint snapshot (seq ${baselineSeq}) but is missing from the response without a verified deletion tombstone (an unexplained omission of a checkpointed value)`;
    }
  }
  return null;
}

/**
 * Enforces client rule 2 of the checkpoint-integrity verification
 * (CRYPTO_SPEC §6.3 — value non-regression) for one value-bearing response.
 * The baseline is always derived from the verifier's own verified chain
 * (`latestCheckpointFor`) — never from server claims; the wire's checkpoint
 * seq / hash is an advisory locator that only routes the §6.3-2-style
 * two-way classification and the evidence messages.
 */
export async function checkCheckpointIntegrity(input: {
  /** Index over the verifier's own fully verified chain snapshot. */
  readonly history: ChainHistoryIndex;
  readonly environmentId: string;
  /** ワイヤの同梱列挙(§12-7 / §14-2)。undefined = 応答に載っていない。 */
  readonly snapshot: CheckpointValueSnapshot | undefined;
  /** §6.3 検証を全通過した配布値(値付き応答のアクティブ集合)。 */
  readonly variables: readonly CheckpointCheckedValue[];
  /** 検証済み tombstone の variableId 集合(マニフェスト整合込み)。 */
  readonly tombstoneIds: ReadonlySet<string>;
  /**
   * 応答を**取得した時点**の検証済みビューのヘッド seq(pull = 取得時ビュー、
   * lease = 同梱チェーンのヘッド)。有界再同期の再検証で history が応答より
   * 前進している場合の良性競合の判別に使う(locatorOutcome の doc)。
   */
  readonly fetchedAtHeadSeq: number;
}): Promise<CheckpointIntegrityOutcome> {
  const { history, environmentId, snapshot } = input;
  const baseline = history.latestCheckpointFor(environmentId);
  if (snapshot === undefined) {
    if (baseline === undefined) {
      // 基準を持たない環境は本検証の対象外(§6.3 — 保証は床・マニフェストの
      // エポック整合のみ。床なしクライアントの警告は呼び出し側の SHOULD)
      return { kind: "ok" };
    }
    if (baseline.seq > input.fetchedAtHeadSeq) {
      // 基準は応答の取得ビューより後に着地した(有界再同期だけが前進した形)。
      // 応答生成時にサーバーが保存行を持たなかった良性の説明が残る — 再 pull
      // が新基準の列挙を持ってくる(locatorOutcome の doc と同じ判別)
      return retriable(
        `A checkpoint covering environment ${displayText(environmentId)} (seq ${baseline.seq}) was accepted after this response's view, and the response carries no snapshot for it. The response may simply predate the checkpoint — retry the pull; if this persists, the server is omitting the checkpoint value snapshot`,
      );
    }
    // 基準あり + 列挙なし = 拒否(MUST — 省略を規則 2 のスキップに落とさせない)
    return rejected(
      `The server omitted the checkpoint value snapshot for environment ${displayText(environmentId)} although the verified chain carries a checkpoint baseline (seq ${baseline.seq}). Omission would disable rollback detection, so the response is rejected (CRYPTO_SPEC §6.3). If the server predates the snapshot-distribution release, update the server first`,
    );
  }
  const locator = locatorOutcome(
    history,
    environmentId,
    snapshot,
    baseline,
    input.fetchedAtHeadSeq,
  );
  if (locator !== null || baseline === undefined) {
    // baseline なしの列挙は locator が必ず future / rejected を返している
    return locator ?? rejected("checkpoint locator inconsistency");
  }
  // 列挙の正規ダイジェスト再計算(重複 variableId は計算側が拒否する)と
  // チェーン公証(values_digest)との照合
  const digest = await computeEnvValuesDigest(SUITE_ID, snapshot.values);
  if (!digest.ok || digest.value !== baseline.valuesDigestHex) {
    return rejected(
      `The checkpoint value snapshot for environment ${displayText(environmentId)} does not match the values digest notarized by checkpoint seq ${baseline.seq} on the verified chain (a tampered or substituted enumeration)`,
    );
  }
  const snapshotById = new Map(snapshot.values.map((entry) => [entry.variableId, entry]));
  for (const value of input.variables) {
    const reason = servedValueReason(value, snapshotById.get(value.variableId), baseline);
    if (reason !== null) {
      return rejected(reason);
    }
  }
  const servedIds = new Set(input.variables.map((value) => value.variableId));
  const omission = omissionReason(snapshot, servedIds, input.tombstoneIds, baseline.seq);
  return omission === null ? { kind: "ok" } : rejected(omission);
}
