import { type EnvironmentId, type UserId, type VariableId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { cliError, type CliError } from "./errors.ts";
import type { FloorHandle } from "./floor-check.ts";
import type { ManifestFloor } from "./floor.ts";
import { type ManifestDigestEntry, type SignedManifest, signNextManifest } from "./manifest.ts";
import { pullVerifiedEnvironmentMetadata, type VerifiedEnvironmentMetadata } from "./values.ts";

export const issueManifestWithIntent = Effect.fn("meta-confirm.issueManifestWithIntent")(
  function* (input: {
    readonly verified: VerifiedProject;
    readonly environmentId: EnvironmentId;
    readonly epoch: number;
    readonly previous: {
      readonly manifestVersion: number;
      readonly signedBytesHashHex: string;
    } | null;
    readonly entries: readonly ManifestDigestEntry[];
    readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
    readonly issuerUserId: UserId;
    readonly signingKey: CryptoKey;
    readonly floor: FloorHandle;
    readonly variableId: VariableId | null;
  }): Effect.fn.Return<{ readonly manifest: SignedManifest; readonly intentId: string }, CliError> {
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
  },
);

export const confirmMetaMutation = Effect.fn("meta-confirm.confirmMetaMutation")(function* (input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
  readonly selfManifest: ManifestFloor;
  readonly intentId: string | null;
  readonly describe: string;
  readonly effectVisible: (metadata: VerifiedEnvironmentMetadata) => boolean;
}): Effect.fn.Return<void, CliError> {
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

interface IssuedStatement {
  readonly metaVersion: number;
  readonly metaSigHashHex: string;
}

export function confirmsIssuedStatement(
  observed: IssuedStatement,
  issued: IssuedStatement,
): boolean {
  return (
    observed.metaVersion > issued.metaVersion ||
    (observed.metaVersion === issued.metaVersion &&
      observed.metaSigHashHex === issued.metaSigHashHex)
  );
}

export function confirmAcceptedMetaMutation(
  input: {
    readonly client: MaruhiClient;
    readonly environmentId: EnvironmentId;
    readonly resync: Effect.Effect<VerifiedProject, CliError>;
    readonly floor: FloorHandle;
  },
  accepted: IssuedStatement & {
    readonly state: { readonly verified: VerifiedProject };
    readonly selfManifest: ManifestFloor;
    readonly intentId: string;
  },
  describe: string,
  effectVisible: (metadata: VerifiedEnvironmentMetadata, issued: IssuedStatement) => boolean,
): Effect.Effect<void, CliError> {
  const issued = { metaVersion: accepted.metaVersion, metaSigHashHex: accepted.metaSigHashHex };
  return confirmMetaMutation({
    client: input.client,
    verified: accepted.state.verified,
    environmentId: input.environmentId,
    resync: input.resync,
    floor: input.floor,
    selfManifest: accepted.selfManifest,
    intentId: accepted.intentId,
    describe,
    effectVisible: (metadata) => effectVisible(metadata, issued),
  });
}
