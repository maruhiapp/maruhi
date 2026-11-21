import type { CheckpointValueSnapshot } from "@maruhi/api-schema";
import { cryptoEffect, type EnvironmentId, type VariableId } from "@maruhi/core";
import type { ChainHistoryIndex, EnvironmentCheckpointState } from "@maruhi/crypto";
import { computeEnvValuesDigest, SUITE_ID } from "@maruhi/crypto";
import { Effect } from "effect";

import { displayText } from "./display.ts";

export interface CheckpointCheckedValue {
  readonly variableId: VariableId;
  readonly version: number;
  readonly epoch: number;
  readonly signedBytesHashHex: string;
}

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

function noBaselineOutcome(
  history: ChainHistoryIndex,
  environmentId: EnvironmentId,
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

function locatorOutcome(
  history: ChainHistoryIndex,
  environmentId: EnvironmentId,
  snapshot: CheckpointValueSnapshot,
  baseline: EnvironmentCheckpointState,
  fetchedAtHeadSeq: number,
): CheckpointIntegrityOutcome | null {
  if (snapshot.chainSeq > history.headSeq) {
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

function servedValueReason(
  value: CheckpointCheckedValue,
  entry: { readonly version: number; readonly valueSigHashHex: string } | undefined,
  baseline: EnvironmentCheckpointState,
): string | null {
  if (entry === undefined) {
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

export async function checkCheckpointIntegrity(input: {
  readonly history: ChainHistoryIndex;
  readonly environmentId: EnvironmentId;
  readonly snapshot: CheckpointValueSnapshot | undefined;
  readonly variables: readonly CheckpointCheckedValue[];
  readonly tombstoneIds: ReadonlySet<string>;
  readonly fetchedAtHeadSeq: number;
}): Promise<CheckpointIntegrityOutcome> {
  const { history, environmentId, snapshot } = input;
  const baseline = history.latestCheckpointFor(environmentId);
  if (snapshot === undefined) {
    if (baseline === undefined) {
      return { kind: "ok" };
    }
    if (baseline.seq > input.fetchedAtHeadSeq) {
      return retriable(
        `A checkpoint covering environment ${displayText(environmentId)} (seq ${baseline.seq}) was accepted after this response's view, and the response carries no snapshot for it. The response may simply predate the checkpoint — retry the pull; if this persists, the server is omitting the checkpoint value snapshot`,
      );
    }
    return rejected(
      `The server omitted the checkpoint value snapshot for environment ${displayText(environmentId)} although the verified chain carries a checkpoint baseline (seq ${baseline.seq}). Omission would disable rollback detection, so the response is rejected (CRYPTO_SPEC §6.3). A conforming server stores that snapshot together with the checkpoint, so report this to the server's operator — only a damaged project store or a misbehaving server produces it (re-issuing a checkpoint cannot repair it)`,
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
