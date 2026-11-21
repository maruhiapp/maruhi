import { type ProjectId, type UserId, cryptoEffect, cryptoPromise } from "@maruhi/core";
import type { ChainEntry, ChainHistoryIndex, ChainState } from "@maruhi/crypto";
import {
  computeChainEntryHash,
  computeUserKeyFingerprint,
  decodeHex,
  encodeHex,
  verifyChainWithHistory,
} from "@maruhi/crypto";
import { Data, Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { type AppliedOperation, appliedOperations } from "./chain-applied.ts";
import { type CliError, cliError, evidenceError } from "./errors.ts";
import { toCliError } from "./failure.ts";

export interface KeyBinding {
  readonly encPubHex: string;
  readonly sigPubHex: string;
  readonly keyFingerprintHex: string;
}

export interface DistributedAttestationWire {
  readonly suite: "maruhi/v1";
  readonly attesterUserId: UserId;
  readonly attesterKeyFingerprintHex: string;
  readonly chainHeadHashHex: string;
  readonly chainHeadSeq: number;
  readonly signatureHex: string;
}

export interface VerifiedProject {
  readonly projectId: ProjectId;
  readonly state: ChainState;
  readonly history: ChainHistoryIndex;
  readonly keyHistory: ReadonlyMap<UserId, readonly KeyBinding[]>;
  readonly entries: readonly ChainEntry[];
  readonly applied: readonly AppliedOperation[];
  readonly attestations: readonly DistributedAttestationWire[];
}

function bindingKey(binding: KeyBinding): string {
  return `${binding.encPubHex}:${binding.sigPubHex}`;
}

class ChainDerivationError extends Data.TaggedError("ChainDerivationError")<{
  readonly message: string;
}> {}

const buildKeyHistory = Effect.fn("chain-sync.buildKeyHistory")(function* (
  applied: readonly AppliedOperation[],
): Effect.fn.Return<ReadonlyMap<UserId, readonly KeyBinding[]>, ChainDerivationError> {
  const history = new Map<UserId, KeyBinding[]>();
  const seen = new Set<string>();
  const add = (userId: UserId, binding: KeyBinding) => {
    const dedupe = `${userId}#${bindingKey(binding)}`;
    if (seen.has(dedupe)) {
      return;
    }
    seen.add(dedupe);
    const list = history.get(userId);
    if (list === undefined) {
      history.set(userId, [binding]);
    } else {
      list.push(binding);
    }
  };
  for (const { seq, operation, actorUserId } of applied) {
    if (
      operation.op !== "genesis" &&
      operation.op !== "add_member" &&
      operation.op !== "add_device"
    ) {
      continue;
    }
    const enc = decodeHex(operation.payload.encPubHex);
    const sig = decodeHex(operation.payload.sigPubHex);
    if (enc === null || sig === null) {
      return yield* Effect.fail(
        new ChainDerivationError({
          message: `Cannot decode the public-key hex in ${operation.op} (seq=${seq})`,
        }),
      );
    }
    const fingerprint = yield* cryptoEffect(() => computeUserKeyFingerprint(enc, sig)).pipe(
      Effect.mapError(
        () =>
          new ChainDerivationError({
            message: `Cannot compute the key fingerprint for ${operation.op} (seq=${seq})`,
          }),
      ),
    );
    add(operation.op === "add_member" ? operation.payload.targetUserId : actorUserId, {
      encPubHex: operation.payload.encPubHex,
      sigPubHex: operation.payload.sigPubHex,
      keyFingerprintHex: encodeHex(fingerprint),
    });
  }
  return history;
});

export const verifyChainSnapshot = Effect.fn("chain-sync.verifyChainSnapshot")(function* (input: {
  readonly projectId: ProjectId;
  readonly entries: readonly ChainEntry[];
  readonly claimedHeadSeq: number;
  readonly claimedHeadHashHex: string;
  readonly attestations?: readonly DistributedAttestationWire[];
}): Effect.fn.Return<VerifiedProject, CliError> {
  const { projectId, entries } = input;
  const { state, history } = yield* cryptoEffect(() => verifyChainWithHistory(entries)).pipe(
    Effect.catchTag(
      "ChainInvalid",
      (error) =>
        Effect.fail(
          evidenceError(
            `Chain verification failed (seq=${error.seq}, reason=${error.reason}). The server may be distributing an invalid chain`,
          ),
        ),
      () =>
        Effect.fail(
          evidenceError(
            "Chain verification failed (seq=0, reason=invalid-payload). The server may be distributing an invalid chain",
          ),
        ),
    ),
  );

  const genesis = entries[0];
  if (genesis === undefined) {
    return yield* Effect.fail(cliError("The chain is empty"));
  }
  const genesisHash = yield* cryptoPromise("computeChainEntryHash", () =>
    computeChainEntryHash(genesis),
  ).pipe(Effect.mapError(() => cliError("Failed to compute the genesis hash (crypto error)")));
  if (genesisHash !== projectId) {
    return yield* Effect.fail(
      evidenceError(
        `The genesis hash does not match the project ID (suspected server-side chain replacement): expected=${projectId} actual=${genesisHash}`,
      ),
    );
  }

  if (state.headSeq !== input.claimedHeadSeq || state.headHashHex !== input.claimedHeadHashHex) {
    return yield* Effect.fail(
      evidenceError(
        "The server-declared chain head does not match the fetched entries (the response contradicts itself)",
      ),
    );
  }

  const applied = appliedOperations(
    entries,
    (seq) => history.entryHashAt(seq),
    new Set(state.pendingProposals.keys()),
  );
  const keyHistory = yield* buildKeyHistory(applied).pipe(
    Effect.catchTag("ChainDerivationError", (error) =>
      Effect.fail(
        cliError(
          `Chain-derivation inconsistency: ${error.message} (cannot build the key index from the verified chain)`,
        ),
      ),
    ),
  );
  return {
    projectId,
    state,
    history,
    keyHistory,
    entries,
    applied,
    attestations: input.attestations ?? [],
  } satisfies VerifiedProject;
});

export const syncProject = Effect.fn("chain-sync.syncProject")(function* (
  client: MaruhiClient,
  projectId: ProjectId,
): Effect.fn.Return<VerifiedProject, CliError> {
  const snapshot = yield* client.membership
    .get({ params: { projectId } })
    .pipe(Effect.mapError(toCliError));
  return yield* verifyChainSnapshot({
    projectId,
    entries: snapshot.entries,
    claimedHeadSeq: snapshot.headSeq,
    claimedHeadHashHex: snapshot.headHashHex,
    attestations: snapshot.attestations.map((a) => ({
      ...a,
      attesterUserId: a.attesterUserId,
    })),
  });
});

function ensureExtensionOf(
  previous: VerifiedProject,
  next: VerifiedProject,
): Effect.Effect<VerifiedProject, CliError> {
  if (
    next.state.headSeq < previous.state.headSeq ||
    next.history.entryHashAt(previous.state.headSeq) !== previous.state.headHashHex
  ) {
    return Effect.fail(
      evidenceError(
        `The re-synced chain is not an extension of the verified view (seq=${previous.state.headSeq}) (evidence of server-side chain replacement / divergence)`,
      ),
    );
  }
  return Effect.succeed(next);
}

export function resyncExtended(
  resync: Effect.Effect<VerifiedProject, CliError>,
  previous: VerifiedProject,
): Effect.Effect<VerifiedProject, CliError> {
  return Effect.flatMap(resync, (next) => ensureExtensionOf(previous, next));
}
