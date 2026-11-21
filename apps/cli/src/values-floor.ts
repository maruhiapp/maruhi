import { type EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import type { VerifiedProject } from "./chain-sync.ts";
import { requireChainEnvironment } from "./deks.ts";
import { type CliError, evidenceError } from "./errors.ts";
import {
  buildEnvironmentFloor,
  checkEnvironmentMetadataPull,
  checkEnvironmentPull,
  type FloorHandle,
  type VerifiedMetaEvidence,
  type VerifiedPullSnapshot,
  type VerifiedTombstone,
  type VerifiedVariableStatement,
} from "./floor-check.ts";
import { formatFloorViolation } from "./floor-evidence.ts";
import type { ManifestFloorIntent } from "./floor.ts";
import type { VerifiedManifest } from "./manifest.ts";

function resolveMetaIntents(
  floor: FloorHandle,
  manifest: VerifiedManifest,
): Effect.Effect<void, CliError> {
  return Effect.forEach(
    floor
      .unresolvedIntents()
      .filter((intent): intent is ManifestFloorIntent => intent.op === "meta-op"),
    (intent) => {
      if (manifest.manifestVersion > intent.manifestVersion) {
        return floor.resolveIntent(intent.id, "superseded");
      }
      if (manifest.manifestVersion === intent.manifestVersion) {
        return floor.resolveIntent(
          intent.id,
          manifest.signedBytesHashHex === intent.manifestSigHashHex ? "accepted" : "not-accepted",
        );
      }
      return Effect.void;
    },
    { discard: true },
  );
}

export const enforceFloor = Effect.fn("values-floor.enforceFloor")(function* (input: {
  readonly floor: FloorHandle;
  readonly baselineView: VerifiedProject;
  readonly commitView: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly snapshot: VerifiedPullSnapshot;
}): Effect.fn.Return<void, CliError> {
  const violation = checkEnvironmentPull(input.floor.current(), input.snapshot);
  if (violation !== null) {
    return yield* Effect.fail(
      evidenceError(
        formatFloorViolation(
          { projectId: input.commitView.projectId, environmentId: input.environmentId },
          violation,
        ),
      ),
    );
  }
  yield* requireChainEnvironment(input.commitView, input.environmentId);
  const baselineEnvironment = input.baselineView.state.environments.get(input.environmentId);
  if (baselineEnvironment === undefined) {
    return;
  }
  yield* input.floor.commitPull(
    buildEnvironmentFloor(baselineEnvironment.currentEpoch, input.snapshot),
    { seq: input.commitView.state.headSeq, hashHex: input.commitView.state.headHashHex },
  );
  yield* resolveMetaIntents(input.floor, input.snapshot.manifest);
});

export const enforceMetadataFloor = Effect.fn("values-floor.enforceMetadataFloor")(
  function* (input: {
    readonly floor: FloorHandle;
    readonly verified: VerifiedProject;
    readonly environmentId: EnvironmentId;
    readonly environment: VerifiedMetaEvidence;
    readonly variables: readonly VerifiedVariableStatement[];
    readonly tombstones: readonly VerifiedTombstone[];
    readonly manifest: VerifiedManifest;
  }): Effect.fn.Return<void, CliError> {
    const violation = checkEnvironmentMetadataPull(input.floor.current(), {
      environment: input.environment,
      variables: input.variables,
      tombstones: input.tombstones,
      manifest: input.manifest,
    });
    if (violation !== null) {
      return yield* Effect.fail(
        evidenceError(
          formatFloorViolation(
            { projectId: input.verified.projectId, environmentId: input.environmentId },
            violation,
          ),
        ),
      );
    }
    const environment = yield* requireChainEnvironment(input.verified, input.environmentId);
    yield* input.floor.commitMetadata(
      {
        observedEpoch: environment.currentEpoch,
        metaVersion: input.environment.metaVersion,
        metaSigHashHex: input.environment.metaSigHashHex,
        manifest: {
          manifestVersion: input.manifest.manifestVersion,
          epoch: input.manifest.epoch,
          manifestSigHashHex: input.manifest.signedBytesHashHex,
        },
      },
      { seq: input.verified.state.headSeq, hashHex: input.verified.state.headHashHex },
    );
    yield* resolveMetaIntents(input.floor, input.manifest);
  },
);
