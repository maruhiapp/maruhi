// standalone(周期)checkpoint の受理と、checkpoint 内容突合の共有実装
// (CRYPTO_SPEC §6.4 / AUTH_SPEC §16-2。2026-08-28 セッション 35 = PR-M2)。
//
// - standalone は汎用チェーン追記 API 経由(§16-2 — クライアント供給の付随
//   データがなく、複合で束ねる別入力がない)。合意規則(形式・role・監査
//   admin・unknown-environment・エポック厳密一致・checkpoint-regression)は
//   verifyChain(chain-accept.ts 経由)が担い、ここは受理ポリシー =
//   **受理時点(適用前)の保存状態との内容突合**とスナップショットの原子保存
// - 突合の語彙は CheckpointStateMismatch(422): environment-deleted /
//   manifest-mismatch / values-digest-mismatch / audit-head-unknown /
//   audit-head-stale。境界同梱分(composite-programs.ts — 突合基準は複合の
//   適用後状態)も values_digest と監査ヘッドの検査をここから共有し、
//   「保存規律は経路によらず同一」(§16-2)を実装の共有で構造化する
// - 非空 audit_head_hash の実効権限 admin(§16-2): スコープ半分は worker
//   (handlers-membership / handlers-environments)、チェーン role 半分は
//   ここで requireRole(admin) — 不足 403。合意規則の
//   checkpoint-audit-role-insufficient(422)より API の 403 が先に立つ
//   (session-27 §13-5 の権限マトリクス (c))

import type { ChainEntry, CheckpointEnvironmentEntry } from "@maruhi/crypto";
import { computeEnvValuesDigest, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import { AuditStore } from "./audit-store.ts";
import { ensureParentHead, verifyAcceptableEntry } from "./chain-accept.ts";
import { commitAcceptedEntry } from "./chain-commit.ts";
import type { StateCache } from "./chain-store.ts";
import { deriveStoredState, updateStateCache } from "./chain-store.ts";
import { loadInitializedChain, rejectData, requireRole } from "./data-plane.ts";
import type { CheckpointValueEntryRow } from "./data-store.ts";
import { DataStore } from "./data-store.ts";
import { ensureStorageAdmitsAuditHeadExtension } from "./storage-guard.ts";

/**
 * checkpoint values_digest の内容突合(CRYPTO_SPEC §6.4)。`values` は受理
 * 時点(standalone)/ 複合の適用後(境界 — 複合は値を変更しないため同値)の
 * 保存状態の再列挙。不一致は 422(発行者のビューが古い・並行 push)。
 */
export const ensureCheckpointValuesDigest = (
  tuple: CheckpointEnvironmentEntry,
  values: readonly CheckpointValueEntryRow[],
) =>
  Effect.gen(function* () {
    const digest = yield* Effect.promise(() => computeEnvValuesDigest(SUITE_ID, values));
    if (!digest.ok) {
      // 保存行由来の入力で構造不正は実装バグ(エラー値に秘密は含まれない)
      return yield* Effect.die(new Error(`values digest failed: ${digest.error.kind}`));
    }
    if (digest.value !== tuple.valuesDigestHex) {
      return yield* rejectData({
        kind: "checkpoint-state-mismatch",
        reason: "values-digest-mismatch",
      });
    }
  });

/**
 * 非空 audit_head_hash の存在・位置検査(CRYPTO_SPEC §6.4 / AUDIT_SPEC §5.1)。
 * 空文字列 = 公証なしは検査対象外。検査の前に累積ハッシュ列を MAX(seq) まで
 * 伸ばす(遅延 materialize — audit-store.ts)。
 *
 * - 有界伸長(セッション 38): 伸長が 1 呼び出しの上限に達し MAX(seq) 未到達の
 *   場合は retryable な audit-head-not-ready(503)で拒否する。**古い列で
 *   unknown / stale を判定しない**(fail-closed — 途中までの列に対する所属・
 *   位置の判定は、正当な申告の誤拒否〔unknown〕と保護接頭辞の誤った基底を
 *   同時に作る)。進捗は保存済みで、再試行は必ず前進する
 * - 所属: 申告ハッシュが計算列に存在すること(audit-head-unknown)
 * - 位置下限: 出現位置が直前 checkpoint(公証の有無を問わない)のミラー行
 *   (chain.checkpointed)以上であること(audit-head-stale)。直前が存在しない
 *   初回は課さない(空虚に真 — admin 突合〔AUDIT_SPEC §6〕と同一述語・同一の
 *   基底ケース)。この受理検査により、正直なサーバーの下では突合の位置検査が
 *   構造的に必ず成立する(CAS 競合後に申告を取り直さなかった良性の発行は
 *   ここで型付き拒否され、改竄告発として現れない)
 */
export const ensureAuditHeadAcceptable = (auditHeadHashHex: string) =>
  Effect.gen(function* () {
    if (auditHeadHashHex === "") {
      return;
    }
    const audit = yield* AuditStore;
    // DO ストレージ総量ガード(AUTH_SPEC §12-8 — H2): 派生列の実体化(監査
    // 行数比例の書き込み)を要するときだけ成長面として判定する。空の公証
    // (CLI の境界 / 周期 checkpoint)はここへ来ない = 拒否下でも受理される
    yield* ensureStorageAdmitsAuditHeadExtension;
    if ((yield* audit.ensureHeadCurrent) === "more-remains") {
      return yield* rejectData({ kind: "audit-head-not-ready" });
    }
    const position = audit.headPositionSync(auditHeadHashHex);
    if (position === null) {
      return yield* rejectData({ kind: "checkpoint-state-mismatch", reason: "audit-head-unknown" });
    }
    const floor = audit.latestCheckpointMirrorSeqSync();
    if (floor !== null && position < floor) {
      return yield* rejectData({ kind: "checkpoint-state-mismatch", reason: "audit-head-stale" });
    }
  });

/**
 * 1 環境タプルの受理時点突合(§6.4): tombstone(environment-deleted)→
 * 最新マニフェストとの一致(manifest-mismatch — 実在しない先行
 * manifest_version の公証もここで落ちる。session-33 §5 の申し送り)→
 * values_digest。通過したら保存済みの値列挙(スナップショット保存の材料)を
 * 返す。環境のチェーン存在は合意規則(unknown-environment)が先に保証して
 * いる前提 — チェーンに在るのにデータ行が無いのは複合受理の原子性違反
 * (ストレージ破損)なので defect にする。
 */
const ensureCheckpointTupleState = (tuple: CheckpointEnvironmentEntry) =>
  Effect.gen(function* () {
    const store = yield* DataStore;
    const environment = yield* store.findEnvironment(tuple.environmentId);
    if (environment === null) {
      return yield* Effect.die(
        new Error("environment on the verified chain has no data row (composite atomicity)"),
      );
    }
    if (environment.deletedAtMs !== null) {
      return yield* rejectData({
        kind: "checkpoint-state-mismatch",
        reason: "environment-deleted",
      });
    }
    const anchor = yield* store.environmentManifestAnchor(tuple.environmentId);
    if (
      anchor === null ||
      anchor.manifestVersion !== tuple.manifestVersion ||
      anchor.signedBytesHashHex !== tuple.manifestSigHashHex
    ) {
      return yield* rejectData({ kind: "checkpoint-state-mismatch", reason: "manifest-mismatch" });
    }
    const values = yield* store.checkpointValueEntries(tuple.environmentId);
    yield* ensureCheckpointValuesDigest(tuple, values);
    return values;
  });

/**
 * standalone checkpoint の受理(汎用チェーン追記の checkpoint 分岐 —
 * chain-do.ts の appendProgram から呼ばれる)。チェーン追記 + ミラー +
 * スナップショット upsert を単一の同期ブロックで原子コミットする
 * (§16-2 の「チェーン追記と同一トランザクション」。payload に含まれない
 * 環境の既存スナップショットは変更しない)。
 */
export function standaloneCheckpointProgram(
  parentHeadHashHex: string,
  entry: ChainEntry & { readonly op: "checkpoint" },
  callerUserId: string,
  cache: StateCache,
) {
  return Effect.gen(function* () {
    const chain = yield* loadInitializedChain;
    const { state } = yield* deriveStoredState(chain, cache);
    // §11-2: 非メンバーには一切を返さない(worker が 404 に写す)。checkpoint
    // 自体の role 下限(member)は合意規則(verifyChain)が 422 で拒否する
    yield* requireRole(state, callerUserId, "reader");
    // §16-2: 非空 audit_head_hash はチェーン role admin 以上(不足 403。
    // スコープ半分〔admin スコープ〕は worker が先行検査済み)
    if (entry.payload.auditHeadHashHex !== "") {
      yield* requireRole(state, callerUserId, "admin");
    }
    yield* ensureParentHead(chain, parentHeadHashHex);
    // 受理 4 手順(サイズ → 容量 → verifyChain = §6.2 の合意規則)は他経路と共有
    const { canonicalBytes, applied } = yield* verifyAcceptableEntry(chain, entry);
    // 受理時点(適用前)の保存状態との内容突合(§6.4)。列挙順 = payload 順
    const snapshots: {
      readonly tuple: CheckpointEnvironmentEntry;
      readonly values: readonly CheckpointValueEntryRow[];
    }[] = [];
    for (const tuple of entry.payload.environments) {
      snapshots.push({ tuple, values: yield* ensureCheckpointTupleState(tuple) });
    }
    yield* ensureAuditHeadAcceptable(entry.payload.auditHeadHashHex);
    const dataStore = yield* DataStore;
    // スナップショット保存(§6.4)はチェーン挿入・ミラーと同じ同期ブロックで
    // 原子コミットする(commitAcceptedEntry の extraSync)
    yield* commitAcceptedEntry(entry, applied, canonicalBytes, (nowMs) => {
      for (const { tuple, values } of snapshots) {
        dataStore.write.upsertCheckpointSnapshot(
          tuple.environmentId,
          {
            chainSeq: entry.seq,
            entryHashHex: applied.state.headHashHex,
            epoch: tuple.epoch,
            manifestVersion: tuple.manifestVersion,
            manifestSigHashHex: tuple.manifestSigHashHex,
            valuesDigestHex: tuple.valuesDigestHex,
          },
          values,
          nowMs,
        );
      }
    });
    updateStateCache(cache, applied);
    return { headSeq: applied.state.headSeq, headHashHex: applied.state.headHashHex };
  });
}
