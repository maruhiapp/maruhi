// The "applied operations" column of a verified chain (design record
// es-design.md §12 K6-C).
//
// Under four-eyes (CRYPTO_SPEC §6.2 — PF1), an inner op is applied at the
// seq of the `approve` entry that reached quorum, not at the `propose`
// entry (the inclusive convention). When the CLI asks "what happened on
// the chain" (rotation obligations, deletion records, scope-change
// history, the §5.1 key index), the input is this column rather than the
// entry column — giving direct appends and proposal-mediated applies the
// same shape closes the "overlooked a proposal-mediated apply" class of
// defect at a single derivation. Completion is judged by core's
// `indexProposals` (shared with the server's mirror mapping — K5-F).

import { indexProposals, type ProposalIndex } from "@maruhi/core";
import type { ChainEntry, ProposableOperation } from "@maruhi/crypto";

import type { VerifiedProject } from "./sync.ts";

/**
 * The proposal index of a verified view (judging completed / withdrawn —
 * applies core's `indexProposals` to a `VerifiedProject`. K5-F: the
 * server's mirror mapping and the CLI share the same derivation).
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
 * Derives the applied-operations column. `propose` / incomplete `approve` /
 * `withdraw` change no state, so they are not listed. `entryHashAt` and
 * `pendingHashes` are passed from the verified chain's derived state
 * (sync.ts derives them once and carries them as `VerifiedProject.applied`).
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
