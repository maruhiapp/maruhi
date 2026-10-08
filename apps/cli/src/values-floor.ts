// The floor discipline of a verified distribution (CRYPTO_SPEC §6.3):
// check against the last successful pull's baseline, then commit the new
// baseline and reconcile unresolved meta intents.

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

/**
 * Reconciling meta-op intents against a verified distribution (§6.3 record
 * discipline (ii) — 3-F). If the verified manifest reached or passed the
 * intent's version, the confirmation duty can resolve:
 * - same version, same hash = my issuance is being distributed (accepted)
 * - same version, different hash = my issuance was not stored
 *   (not-accepted — the distributed verified manifest is already joined
 *   into the floor as an observation, so the evidence is not lost)
 * - advanced = the duty fulfilled by observing a verified successor state
 *   (superseded)
 * - the distributed version older than the intent = left unresolved
 *   (carried over to the next reconciliation opportunity)
 */
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

/**
 * The floor check (§6.3's (a)(b)(c)) and the floor commit (the update
 * ordering norm: checks run against the last successful pull's baseline,
 * and the baseline's advance is committed atomically with the variable
 * floors after verification succeeds). Every check compares data that
 * passed signature verification, so a disagreement is non-repudiable
 * evidence and every case is refused (the strong side of §6.3's "reject vs
 * warn").
 *
 * The commit point is the §6.3 verification success (a later wrap
 * verification / decryption failure never rolls the floor back — only
 * signature-verified digests are recorded, and the baseline monotonicity
 * argument is independent of decryption success. The "verification" of "a
 * successful pull (verification included)" is read as §6.3).
 */
export const enforceFloor = Effect.fn("values-floor.enforceFloor")(function* (input: {
  readonly floor: FloorHandle;
  /**
   * The view used to derive the rule (c) baseline. **It must be the view
   * verified before the pull response was fetched**: deriving the baseline
   * from a view newer than the response (after a future head's bounded
   * resync) over-advances the baseline across a rotate that landed between
   * the response generation and the resync, and the next pull would
   * falsely refuse "a legitimate old-epoch latest value after a rotation,
   * before re-encryption completes" (§12-7) (applying §6.3's "never advance
   * the baseline on a chain sync alone" norm to the resync path). With
   * baseline ≤ the epoch at response-generation time, the epoch of every
   * legitimate push accepted later is always ≥ the baseline, so no false
   * rejection.
   */
  readonly baselineView: VerifiedProject;
  /** The view used for verification (the commit value of the floor's chain head). */
  readonly commitView: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly snapshot: VerifiedPullSnapshot;
}): Effect.fn.Return<void, CliError> {
  const violation = checkEnvironmentPull(input.floor.current(), input.snapshot);
  if (violation !== null) {
    // Refuse + presentable evidence (coordinates, both signed-bytes
    // hashes, declared heads). A floor violation is a contradiction
    // between properly signed data = evidence (a re-run does not resolve
    // it)
    return yield* Effect.fail(
      evidenceError(
        formatFloorViolation(
          { projectId: input.commitView.projectId, environmentId: input.environmentId },
          violation,
        ),
      ),
    );
  }
  // A distribution that passes verification for an environment absent
  // from the chain stops here (meta carries no epoch anchor, so in an
  // environment with zero variables statement verification alone cannot
  // detect it)
  yield* requireChainEnvironment(input.commitView, input.environmentId);
  // The rule (c) baseline's advance value = the pre-response-fetch
  // view's chain-derived current epoch (§6.2 — the server-claimed
  // currentEpoch is never used)
  const baselineEnvironment = input.baselineView.state.environments.get(input.environmentId);
  if (baselineEnvironment === undefined) {
    // The rare race where the environment was created between the
    // response fetch and the resync: there is no view to derive the
    // baseline from without over-advancing it, so this commit is skipped
    // (established on the next pull. The floor is a SHOULD — the
    // detection material is just established one cycle late; no false
    // detection)
    return;
  }
  yield* input.floor.commitPull(
    buildEnvironmentFloor(baselineEnvironment.currentEpoch, input.snapshot),
    { seq: input.commitView.state.headSeq, hashHex: input.commitView.state.headHashHex },
  );
  // A verified distribution arrived, so reconcile this environment's unresolved meta intents (3-F)
  yield* resolveMetaIntents(input.floor, input.snapshot.manifest);
});

/**
 * The floor check of a metadata-only pull (the valueless shape — only the
 * meta-level rules (a)(b) and omission / undeletion. See
 * checkEnvironmentMetadataPull) and the **environment-level floor commit**
 * (session-31 §3 M1-A3): join the chain head, the environment meta floor,
 * the manifest floor, and the environment-level epoch observation (§6.3
 * coordinate (ii)). **Never fabricate a value floor, never advance the
 * pull baseline (rule (c))** — deriving a value-level baseline from an
 * observation that read no values would falsely refuse a legitimate
 * old-epoch value after a rotation, before re-encryption completes
 * (§6.3's norm).
 */
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
      // A floor violation is a contradiction between properly signed data = evidence (same as the value pull's enforceFloor)
      return yield* Effect.fail(
        evidenceError(
          formatFloorViolation(
            { projectId: input.verified.projectId, environmentId: input.environmentId },
            violation,
          ),
        ),
      );
    }
    // A distribution that passes verification for an environment absent
    // from the chain stops here (the same phantom-environment check as
    // enforceFloor — meta carries no epoch anchor)
    const environment = yield* requireChainEnvironment(input.verified, input.environmentId);
    // The join of verified facts (§6.3 — a single recording rule, not an
    // enumeration of recording triggers). journal-before-release:
    // persisting the append precedes using the pass or reporting success
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
    // A verified distribution arrived, so reconcile this environment's unresolved meta intents (3-F)
    yield* resolveMetaIntents(input.floor, input.manifest);
  },
);
