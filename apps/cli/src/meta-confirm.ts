// Shared implementation of effect-confirmation for meta operations
// (variable creation, activation, schema set) (AUTH_SPEC §12-10 (3)
// — 1-E′): success is not "a 2xx was received" but "the effect was
// confirmed on a verifiable distribution". The check material is a
// metadata-only pull (the path that records no var.read — §12-7),
// and it collates the (version, signed-bytes hash) of the
// self-issued manifest.
//
// - The distributed manifest exactly matches the self-issued one →
//   confirmed (the floor's manifest advance is already joined by
//   the confirmation pull's verified observation —
//   enforceMetadataFloor)
// - The version has advanced but the operation's effect is visible
//   from the verified set (effectVisible — creation = the
//   random-issued ID's presence; activation / schema re-issuance = a
//   statement at or above the issued metaVersion) → confirmed (the
//   form of being overtaken by a concurrent meta operation)
// - Manifest missing, a different manifest (same version,
//   different hash), or the effect absent → failure. **The floor
//   does NOT advance to the self-issued manifest** (do not write
//   my assumption onto the floor — only verified observations are
//   recorded)

import type { EnvironmentId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle } from "./floor-check.ts";
import type { ManifestFloor } from "./floor.ts";
import { type ManifestDigestEntry, type SignedManifest, signNextManifest } from "./manifest.ts";
import { pullVerifiedEnvironmentMetadata, type VerifiedEnvironmentMetadata } from "./values.ts";

/**
 * The shared first half of a meta operation's compound send
 * (push's create / activation, schema set): issuing a manifest that
 * reflects the post-operation meta set (§4.3 / §12-5) and appending
 * the pre-send intent (3-F — journal-before-send). When persisting
 * the intent fails, the caller must not send (fail-closed —
 * appendIntent's failure propagates as is).
 */
export function issueManifestWithIntent(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: string;
  /** The current epoch at issuance time (the chain-derived value). */
  readonly epoch: number;
  readonly previous: {
    readonly manifestVersion: number;
    readonly signedBytesHashHex: string;
  } | null;
  /** The meta set after the operation is applied (tombstones included — §4.3 (3)'s recomputation target). */
  readonly entries: readonly ManifestDigestEntry[];
  readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
  readonly issuerUserId: string;
  readonly signingKey: CryptoKey;
  readonly floor: FloorHandle;
  /** The intent's collation coordinate (the meta operation's target variable). */
  readonly variableId: string;
}): Effect.Effect<{ readonly manifest: SignedManifest; readonly intentId: string }, CliError> {
  return Effect.gen(function* () {
    const chainHead = {
      seq: input.verified.state.headSeq,
      hashHex: input.verified.state.headHashHex,
    };
    const manifest = yield* signNextManifest({
      verified: input.verified,
      environmentId: input.environmentId,
      epoch: input.epoch,
      previous: input.previous,
      entries: input.entries,
      envMeta: input.envMeta,
      issuerUserId: input.issuerUserId,
      signingKey: input.signingKey,
      chainHead,
    });
    const intentId = yield* input.floor.appendIntent({
      op: "meta-op",
      environmentId: input.environmentId,
      epoch: input.epoch,
      dekCommitmentHex: null,
      variableId: input.variableId,
      manifestVersion: manifest.manifestVersion,
      manifestSigHashHex: manifest.manifestSigHashHex,
      declaredHead: chainHead,
    });
    return { manifest, intentId };
  });
}

/**
 * Confirms one accepted meta mutation against the verified distribution
 * (AUTH_SPEC §12-10 (3)): resolves the 3-F intent on success, and fails with
 * a typed error when the issued manifest was not stored or the effect is not
 * visible in the verified statement set.
 */
export function confirmMetaMutation(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly selfManifest: ManifestFloor;
  /** The id of the intent (3-F) appended before sending (null = the call shape with no intent). */
  readonly intentId: string | null;
  /** The operation's English name (for wording — e.g. "variable creation" / "activation"). */
  readonly describe: string;
  /**
   * Effect confirmation for when the manifest version has
   * overtaken the self-issued one (whether this operation's effect
   * is visible from the verified set). Creation = the random-issued
   * ID's presence; continuing statement = a statement / tombstone
   * at or above the issued metaVersion.
   */
  readonly effectVisible: (metadata: VerifiedEnvironmentMetadata) => boolean;
}): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const metadata = yield* pullVerifiedEnvironmentMetadata({
      client: input.client,
      verified: input.verified,
      environmentId: input.environmentId,
      resync: input.resync,
      floor: input.floor,
    }).pipe(
      Effect.mapError((error) =>
        cliError(
          `The ${input.describe} was accepted (2xx), but the post-acceptance confirmation against the verified distribution failed (AUTH_SPEC §12-10 (3) — success is defined by the confirmed effect, not the 2xx): ${error.message}`,
        ),
      ),
    );
    const distributed = metadata.manifest;
    const resolve = (outcome: Parameters<FloorHandle["resolveIntent"]>[1]) =>
      input.intentId === null ? Effect.void : input.floor.resolveIntent(input.intentId, outcome);
    if (
      distributed.manifestVersion === input.selfManifest.manifestVersion &&
      distributed.signedBytesHashHex === input.selfManifest.manifestSigHashHex
    ) {
      return yield* resolve("accepted");
    }
    if (
      distributed.manifestVersion > input.selfManifest.manifestVersion &&
      input.effectVisible(metadata)
    ) {
      // Overtaken by a concurrent meta operation, but this operation's effect exists in the verified set
      return yield* resolve("accepted-superseded");
    }
    if (distributed.manifestVersion === input.selfManifest.manifestVersion) {
      yield* resolve("not-accepted");
      return yield* Effect.fail(
        cliError(
          `The ${input.describe} was accepted (2xx), but the server distributes a different manifest at the issued manifestVersion ${input.selfManifest.manifestVersion} (issued signed-bytes hash ${input.selfManifest.manifestSigHashHex}, distributed ${distributed.signedBytesHashHex}). The issued manifest was not stored — treating the ${input.describe} as unconfirmed (AUTH_SPEC §12-10 (3)); the local floor was not advanced with the issued manifest`,
        ),
      );
    }
    return yield* Effect.fail(
      cliError(
        `The ${input.describe} was accepted (2xx), but its effect could not be confirmed in the verified distribution (the distributed manifestVersion is ${distributed.manifestVersion} vs the issued ${input.selfManifest.manifestVersion}, and the effect is not visible in the verified statement set). Treating the ${input.describe} as unconfirmed (AUTH_SPEC §12-10 (3)) — re-run the command after investigating the server`,
      ),
    );
  });
}
