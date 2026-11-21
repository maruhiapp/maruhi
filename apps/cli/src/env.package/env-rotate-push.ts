import type { VariableId } from "@maruhi/core";
import { Effect } from "effect";

import { resyncExtended, type VerifiedProject } from "../chain-sync.ts";
import { requireChainEnvironment } from "../deks.ts";
import { displayText } from "../display.ts";
import { CliError, cliError } from "../errors.ts";
import { toCliError } from "../failure.ts";
import { missingWrapReason } from "../pull.ts";
import { encryptAndSignPayload, winnerInconsistency } from "../push.package/index.ts";
import type { VerifiedPulledValue } from "../values-verify.ts";
import { pullVerifiedEnvironment } from "../values.ts";
import { decryptTargets, undecryptableWarning } from "./env-rotate-decrypt.ts";
import {
  type ConflictedTarget,
  type ReencryptTarget,
  type ReencryptContext,
  asOutcome,
} from "./env-rotate-shared.ts";

type PushAttempt =
  | {
      readonly kind: "pushed";
      readonly floorWarning: string | null;
      readonly written: VerifiedPulledValue;
    }
  | { readonly kind: "conflict"; readonly currentVersion: number }
  | { readonly kind: "deleted" }
  | { readonly kind: "epoch-stale" };

export const pushReencrypted = Effect.fn("env-rotate-push.pushReencrypted")(function* (input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  readonly target: ReencryptTarget;
}): Effect.fn.Return<PushAttempt, CliError> {
  const { environmentId, epoch, dek, writerUserId, signingKey, floor, client } = input.context;
  const latest = input.target.value;
  const version = latest.version + 1;
  const signed = yield* encryptAndSignPayload({
    verified: input.view,
    environmentId: environmentId,
    variableId: latest.variableId,
    epoch: epoch,
    version,
    prevValueSigHashHex: latest.signedBytesHashHex,
    dek: dek,
    value: input.target.plaintext,
    writerUserId: writerUserId,
    signingKey: signingKey,
  });
  const outcome = yield* client.variables
    .push({
      params: {
        projectId: input.view.projectId,
        environmentId: environmentId,
        variableId: latest.variableId,
      },
      payload: { value: signed.payload, sameValueAs: latest.version },
    })
    .pipe(
      Effect.map(() => ({ kind: "pushed" }) as const),
      Effect.catchTags(
        {
          VersionConflict: (error) =>
            Effect.succeed({
              kind: "conflict",
              currentVersion: error.currentVersion,
            } satisfies PushAttempt),
          VariableNotFound: () => Effect.succeed({ kind: "deleted" } satisfies PushAttempt),
          EpochConflict: () => Effect.succeed({ kind: "epoch-stale" } satisfies PushAttempt),
        },
        (error) => Effect.fail(toCliError(error)),
      ),
    );
  if (outcome.kind !== "pushed") {
    return outcome;
  }
  const floorWarning = yield* floor
    .commitPush(
      latest.variableId,
      {
        status: "active",
        version,
        epoch: epoch,
        valueSigHashHex: signed.signedBytesHashHex,
        metaVersion: latest.metaVersion,
        metaSigHashHex: latest.metaSignedBytesHashHex,
      },
      { seq: input.view.state.headSeq, hashHex: input.view.state.headHashHex },
    )
    .pipe(
      Effect.as(null),
      Effect.catch((error) =>
        Effect.succeed(
          `Re-encryption of variable ${displayText(latest.name)} was accepted, but ${error.message} (some rollback-detection material for this variable is missing)`,
        ),
      ),
    );
  const written: VerifiedPulledValue = {
    ...latest,
    version,
    epoch,
    nonceHex: signed.payload.nonceHex,
    ciphertextHex: signed.payload.ciphertextHex,
    prevValueSigHashHex: latest.signedBytesHashHex,
    signedBytesHashHex: signed.signedBytesHashHex,
    valueChainHeadSeq: input.view.state.headSeq,
    valueChainHeadHashHex: input.view.state.headHashHex,
    valueSignatureHex: signed.payload.signatureHex,
    writerUserId,
    writerKeyFingerprintHex: input.context.writerKeyFingerprintHex,
  };
  return { kind: "pushed", floorWarning, written };
});

function reconcileKnown(input: {
  readonly known: ReadonlyMap<VariableId, ConflictedTarget>;
  readonly unfinishedIds: ReadonlySet<VariableId>;
  readonly latest: readonly VerifiedPulledValue[];
  readonly epoch: number;
  readonly collectWarning: (warning: string) => void;
}): { readonly evidence: string | null; readonly alreadyCurrent: number } {
  const latestById = new Map(input.latest.map((value) => [value.variableId, value]));
  let alreadyCurrent = 0;
  for (const [variableId, previous] of input.known) {
    const latest = latestById.get(variableId);
    if (latest === undefined) {
      if (input.unfinishedIds.has(variableId)) {
        input.collectWarning(
          `Variable ${displayText(previous.known.name)} is no longer in the re-fetched active set (concurrently deleted by another member). Removing it from the re-encryption targets`,
        );
      }
      continue;
    }
    const inconsistency = winnerInconsistency(
      variableId,
      previous.known,
      latest,
      previous.currentVersion,
    );
    if (inconsistency !== null) {
      return { evidence: inconsistency, alreadyCurrent: 0 };
    }
    if (input.unfinishedIds.has(variableId) && latest.epoch >= input.epoch) {
      alreadyCurrent += 1;
    }
  }
  return { evidence: null, alreadyCurrent };
}

interface RescanResult {
  readonly view: VerifiedProject;
  readonly stale: readonly VerifiedPulledValue[];
  readonly targets: readonly ReencryptTarget[];
  readonly undecryptable: readonly string[];
  readonly alreadyCurrent: number;
  readonly evidence: string | null;
}

export const rescanEnvironment = Effect.fn("env-rotate-push.rescanEnvironment")(function* (input: {
  readonly context: ReencryptContext;
  readonly view: VerifiedProject;
  readonly known: ReadonlyMap<VariableId, ConflictedTarget>;
  readonly unfinishedIds: ReadonlySet<VariableId>;
  readonly collectWarning: (warning: string) => void;
  readonly forceResync: boolean;
  readonly decryptRemaining: boolean;
}): Effect.fn.Return<RescanResult, CliError> {
  const { client, environmentId, resync, floor, epoch, deksByEpoch } = input.context;
  const base = input.forceResync ? yield* resyncExtended(resync, input.view) : input.view;
  const pulled = yield* pullVerifiedEnvironment({
    client,
    verified: base,
    environmentId,
    resync,
    floor,
  });
  const view = pulled.verified;
  for (const warning of pulled.warnings) {
    input.collectWarning(warning);
  }
  const environment = yield* requireChainEnvironment(view, environmentId);
  if (environment.currentEpoch !== epoch) {
    return yield* Effect.fail(
      cliError(
        `Environment ${environmentId}'s epoch advanced from ${epoch} to ${environment.currentEpoch} during re-encryption (a concurrent rotation by another member)`,
      ),
    );
  }
  const reconciled = reconcileKnown({
    known: input.known,
    unfinishedIds: input.unfinishedIds,
    latest: pulled.variables,
    epoch,
    collectWarning: input.collectWarning,
  });
  if (reconciled.evidence !== null) {
    return {
      view,
      stale: [],
      targets: [],
      undecryptable: [],
      alreadyCurrent: 0,
      evidence: reconciled.evidence,
    };
  }
  const stale = pulled.variables.filter((value) => value.epoch < epoch);
  if (!input.decryptRemaining) {
    const missing = stale.filter((value) => !deksByEpoch.has(value.epoch)).map(missingWrapReason);
    for (const reason of missing) {
      input.collectWarning(undecryptableWarning(reason));
    }
    return {
      view,
      stale,
      targets: [],
      undecryptable: missing,
      alreadyCurrent: reconciled.alreadyCurrent,
      evidence: null,
    };
  }
  const attempted = yield* asOutcome(
    decryptTargets({
      verified: view,
      environmentId,
      values: stale,
      deksByEpoch,
      chainEpoch: environment.currentEpoch,
    }),
  );
  if (attempted.kind === "failed") {
    return {
      view,
      stale,
      targets: [],
      undecryptable: [],
      alreadyCurrent: 0,
      evidence: attempted.error.message,
    };
  }
  const decrypted = attempted.value;
  for (const reason of decrypted.undecryptable) {
    input.collectWarning(undecryptableWarning(reason));
  }
  return {
    view,
    stale,
    targets: decrypted.targets,
    undecryptable: decrypted.undecryptable,
    alreadyCurrent: reconciled.alreadyCurrent,
    evidence: null,
  };
});
