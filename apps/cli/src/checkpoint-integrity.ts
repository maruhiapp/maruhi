// Client rule 2 of checkpoint integrity (CRYPTO_SPEC §6.3 — value
// non-regression).
//
// The per-environment baseline is **the latest `checkpoint` containing an
// entry of that environment** on the verified chain
// (history.latestCheckpointFor — a server-independent chain derivation). It
// checks the "enumeration of the value snapshot at checkpoint time" bundled
// with a value-bearing response (bulk pull §12-7 / lease §14-2):
//
//   1. **baseline exists + no enumeration = refuse (MUST)** — do not let
//      omitting the enumeration slide into "rule 2 skipped" (whether a
//      baseline exists is decidable server-independently from the verified
//      chain)
//   2. The wire's corresponding checkpoint seq / hash is an **advisory
//      locator** (session-36 ruling S — the verification baseline is always
//      chain-derived). The same two-way classification as §6.3-2's head
//      binding: declared seq > own head = possibly just a stale local chain
//      (future — pull resolves it via bounded resync; for lease the same
//      response bundles the chain, so it is a self-contradiction = refuse
//      immediately) / declared seq ≤ own head = the baseline is settled and
//      a mismatch is hard evidence
//   3. The enumeration's recomputed digest (computeEnvValuesDigest — the
//      vector-pinned canonical form) equals the baseline's values_digest
//   4. For each served variable: version at or above the snapshot; on
//      equality, the value_signed_bytes hash matches; a version newer than
//      the snapshot has epoch at or above the baseline epoch (the checkpoint
//      version of floor rule (c) — this is what detects forward injection
//      into a floorless client)
//   5. A variable present in the snapshot but absent in the distribution is
//      refused as an omission unless a verified tombstone (including
//      manifest consistency — the caller places this check after the
//      manifest stage) explains the deletion
//   6. A served variable absent from the snapshot may be a legitimate
//      post-checkpoint creation (the epoch baseline — isomorphic to floor
//      rule (c)'s "version 0 equivalent". Manifest consistency is already
//      guaranteed by the preceding digest recomputation)
//
// An environment without a baseline is outside this verification (the
// guarantee is only the floor / manifest epoch consistency — §6.3). The
// "no baseline" warning (SHOULD) for a floorless client (a workload — §9.1)
// is carried by the lease path's caller (session-36 ruling V).
//
// The inspected variables / tombstones are data that passed all §6.3
// signature verification and the baseline is a value derived from the
// verified chain, so a mismatch here is a contradiction between
// properly-signed data and a chain notarization = evidence of a server
// rollback, forward injection, or tampering, and everything is refused (the
// caller types it as evidence — errors.ts).

import type { CheckpointValueSnapshot } from "@maruhi/api-schema";
import { cryptoEffect } from "@maruhi/core";
import type { ChainHistoryIndex, EnvironmentCheckpointState } from "@maruhi/crypto";
import { computeEnvValuesDigest, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import { displayText } from "./display.ts";

/** The coordinates of a served value that rule 2 looks at (satisfied by values-verify.ts's VerifiedPulledValue). */
export interface CheckpointCheckedValue {
  readonly variableId: string;
  readonly version: number;
  readonly epoch: number;
  /** The self-computed value_signed_bytes hash (§4.1 — not a claimed value). */
  readonly signedBytesHashHex: string;
}

/**
 * Rule 2's verdict (future = the §6.3-2b-isomorphic "possibly just a stale
 * local chain"). rejected's evidence types whether it is "a contradiction
 * between verified data and a chain notarization = evidence a re-run will
 * not resolve" (false = a shape also explainable by the benign race where
 * the baseline advanced after the response's fetch view — resolvable by
 * re-pulling, so rotate's sweep classification does not escalate it to an
 * evidence interruption).
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
 * Classification of the shape where an enumeration was distributed for an
 * environment with no baseline (the §6.3-2-isomorphic future / refuse). Even
 * when the position is a real entry (hash match), on the chain derivation
 * that entry is not a checkpoint covering the environment (if it covered it,
 * a baseline would have been derived) = fabrication.
 */
function noBaselineOutcome(
  history: ChainHistoryIndex,
  environmentId: string,
  snapshot: CheckpointValueSnapshot,
): CheckpointIntegrityOutcome {
  if (snapshot.chainSeq > history.headSeq) {
    return { kind: "future" };
  }
  if (history.entryHashAt(snapshot.chainSeq) !== snapshot.entryHashHex) {
    return rejected(
      `The served checkpoint value snapshot declares an entry hash for seq ${snapshot.chainSeq} that does not match the verified chain (evidence of chain divergence or forgery)`,
    );
  }
  return rejected(
    `A checkpoint value snapshot claiming checkpoint seq ${snapshot.chainSeq} was served for environment ${displayText(environmentId)}, but the verified chain derives no checkpoint covering this environment (the response contradicts the chain)`,
  );
}

/**
 * Classification of the locator (the declared checkpoint position) (ruling
 * S — §6.3-2-isomorphic). null = the position matches the baseline (continue
 * checking).
 *
 * Bounded resync re-verifies **the same body without refetching the
 * response** under the advanced view (values.ts's pullWithBoundedResync), so
 * the "baseline" may have advanced after the response was fetched. A shape
 * where the baseline landed after the response's fetch view
 * (fetchedAtHeadSeq) can occur with an honest server too (another checkpoint
 * slips into the window between the fetch and the resync) — only this shape
 * is refused as retriable rather than evidence (a re-pull brings the new
 * baseline's enumeration). For a baseline that existed before the fetch view
 * there is no benign explanation: the server stores the snapshot atomically
 * with checkpoint acceptance (§16-2), so a response asserting an old
 * position is evidence of stale distribution or fabrication.
 */
function locatorOutcome(
  history: ChainHistoryIndex,
  environmentId: string,
  snapshot: CheckpointValueSnapshot,
  baseline: EnvironmentCheckpointState,
  fetchedAtHeadSeq: number,
): CheckpointIntegrityOutcome | null {
  if (snapshot.chainSeq > history.headSeq) {
    // Possibly a checkpoint landed just before the response was generated
    // (the local chain is merely stale). pull resolves it via bounded resync;
    // lease's caller refuses it as a self-contradiction
    return { kind: "future" };
  }
  if (history.entryHashAt(snapshot.chainSeq) !== snapshot.entryHashHex) {
    return rejected(
      `The served checkpoint value snapshot declares an entry hash for seq ${snapshot.chainSeq} that does not match the verified chain (evidence of chain divergence or forgery)`,
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

/** The per-variable check of one served variable x snapshot·baseline (§6.3 rule 2). */
function servedValueReason(
  value: CheckpointCheckedValue,
  entry: { readonly version: number; readonly valueSigHashHex: string } | undefined,
  baseline: EnvironmentCheckpointState,
): string | null {
  if (entry === undefined) {
    // May be a legitimate post-checkpoint creation — the epoch baseline (the version 0 equivalent)
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

/** The omission check for a variable present in the snapshot but absent in the distribution (only a tombstone's explanation is admissible). */
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
  /** The wire's bundled enumeration (§12-7 / §14-2). undefined = absent from the response. */
  readonly snapshot: CheckpointValueSnapshot | undefined;
  /** The served values that passed all §6.3 verification (the value-bearing response's active set). */
  readonly variables: readonly CheckpointCheckedValue[];
  /** The variableId set of verified tombstones (including manifest consistency). */
  readonly tombstoneIds: ReadonlySet<string>;
  /**
   * The head seq of the verified view **at the moment the response was
   * fetched** (pull = the fetch-time view, lease = the bundled chain's head).
   * Used to tell the benign race where history has advanced past the
   * response under bounded-resync re-verification (locatorOutcome's doc).
   */
  readonly fetchedAtHeadSeq: number;
}): Promise<CheckpointIntegrityOutcome> {
  const { history, environmentId, snapshot } = input;
  const baseline = history.latestCheckpointFor(environmentId);
  if (snapshot === undefined) {
    if (baseline === undefined) {
      // An environment without a baseline is outside this verification
      // (§6.3 — the guarantee is only the floor / manifest epoch
      // consistency; a floorless client's warning is the caller's SHOULD)
      return { kind: "ok" };
    }
    if (baseline.seq > input.fetchedAtHeadSeq) {
      // The baseline landed after the response's fetch view (the shape where
      // only the bounded resync advanced). A benign explanation remains —
      // the server may not have had the stored row when it generated the
      // response; a re-pull brings the new baseline's enumeration (the same
      // discrimination as locatorOutcome's doc)
      return retriable(
        `A checkpoint covering environment ${displayText(environmentId)} (seq ${baseline.seq}) was accepted after this response's view, and the response carries no snapshot for it. The response may simply predate the checkpoint — retry the pull; if this persists, the server is omitting the checkpoint value snapshot`,
      );
    }
    // Baseline exists + no enumeration = refuse (MUST — omission must
    // not slide into skipping rule 2). The shape where the server has no
    // stored row (normally unreachable — storing is atomic with
    // acceptance §16-2) gets its baseline and stored row re-aligned by
    // issuing a fresh checkpoint
    return rejected(
      `The server omitted the checkpoint value snapshot for environment ${displayText(environmentId)} although the verified chain carries a checkpoint baseline (seq ${baseline.seq}). Omission would disable rollback detection, so the response is rejected (CRYPTO_SPEC §6.3). A project member can re-establish a distributable baseline by issuing a fresh checkpoint: \`maruhi project checkpoint\``,
    );
  }
  if (baseline === undefined) {
    return noBaselineOutcome(history, environmentId, snapshot);
  }
  const locator = locatorOutcome(
    history,
    environmentId,
    snapshot,
    baseline,
    input.fetchedAtHeadSeq,
  );
  if (locator !== null) {
    return locator;
  }
  // Recompute the enumeration's canonical digest (the computation refuses
  // duplicate variableIds) and reconcile it against the chain notarization
  // (values_digest)
  const digest = await Effect.runPromise(
    cryptoEffect(() => computeEnvValuesDigest(SUITE_ID, snapshot.values)).pipe(
      Effect.match({ onSuccess: (value) => value, onFailure: () => null }),
    ),
  );
  if (digest === null || digest !== baseline.valuesDigestHex) {
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
