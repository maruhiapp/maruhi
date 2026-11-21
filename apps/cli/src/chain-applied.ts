import type { UserId } from "@maruhi/core";
import { indexProposals, type ProposalIndex } from "@maruhi/core";
import type { ChainEntry, ProposableOperation } from "@maruhi/crypto";

import type { VerifiedProject } from "./chain-sync.ts";

export function proposalIndexOf(verified: VerifiedProject): ProposalIndex {
  return indexProposals(
    verified.entries,
    (seq) => verified.history.entryHashAt(seq),
    new Set(verified.state.pendingProposals.keys()),
  );
}

export interface AppliedOperation {
  readonly seq: number;
  readonly operation: ProposableOperation;
  readonly actorUserId: UserId;
  readonly viaProposalSeq: number | null;
}

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
