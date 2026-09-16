// 検証済みチェーンの「適用済み操作」列(設計録 es-design.md §12 K6-C)。
//
// 四眼(CRYPTO_SPEC §6.2 — PF1)の下では、内側 op は `propose` エントリではなく
// 定足数に達した `approve` エントリの seq で適用される(inclusive 規約)。CLI が
// 「チェーン上で起きたこと」(ローテーション義務・削除記録・scope 変更の履歴・
// §5.1 の鍵索引)を問うときの入力は、エントリ列ではなくこの列にする — 直接追記と
// 提案経由の適用を同じ形にし、「提案経由の適用を見落とす」型の欠陥を導出 1 箇所で
// 閉じる。完成判定は core の `indexProposals`(サーバーのミラー写像と共有 — K5-F)。

import { indexProposals, type ProposalIndex } from "@maruhi/core";
import type { ChainEntry, ProposableOperation } from "@maruhi/crypto";

import type { VerifiedProject } from "./sync.ts";

/**
 * 検証済みビューの提案索引(完成 / 撤回の判定 — core の `indexProposals` を
 * `VerifiedProject` に適用する。K5-F: サーバーのミラー写像と CLI が同じ導出を共有)。
 */
export function proposalIndexOf(verified: VerifiedProject): ProposalIndex {
  return indexProposals(
    verified.entries,
    (seq) => verified.history.entryHashAt(seq),
    new Set(verified.state.pendingProposals.keys()),
  );
}

/** One operation the chain applied (directly, or as the inner op of a completed `approve`). */
export interface AppliedOperation {
  /** The seq the operation took effect at (the `approve` seq for a proposal). */
  readonly seq: number;
  readonly operation: ProposableOperation;
  /** The actor the operation is attributed to (the proposer for an applied inner op — §6.2). */
  readonly actorUserId: string;
  /** Seq of the `propose` entry when applied through a proposal, else null. */
  readonly viaProposalSeq: number | null;
}

/**
 * 適用済み操作列の導出。`propose` / 未完成の `approve` / `withdraw` は状態を変えない
 * ので載せない。`entryHashAt` と `pendingHashes` は検証済みチェーンの導出状態から
 * 渡す(sync.ts が 1 回だけ導出し、`VerifiedProject.applied` として運ぶ)。
 */
export function appliedOperations(
  entries: readonly ChainEntry[],
  entryHashAt: (seq: number) => string | undefined,
  pendingHashes: ReadonlySet<string>,
): readonly AppliedOperation[] {
  const index = indexProposals(entries, entryHashAt, pendingHashes);
  const applied: AppliedOperation[] = [];
  for (const entry of entries) {
    if (entry.op === "propose" || entry.op === "withdraw") {
      continue;
    }
    if (entry.op === "approve") {
      const proposal = index.get(entry.payload.proposalHashHex);
      if (proposal !== undefined && proposal.completedAtSeq === entry.seq) {
        applied.push({
          seq: entry.seq,
          operation: proposal.entry.payload.inner,
          actorUserId: proposal.entry.actor.userId,
          viaProposalSeq: proposal.entry.seq,
        });
      }
      continue;
    }
    applied.push({
      seq: entry.seq,
      operation: { op: entry.op, payload: entry.payload } as ProposableOperation,
      actorUserId: entry.actor.userId,
      viaProposalSeq: null,
    });
  }
  return applied;
}
