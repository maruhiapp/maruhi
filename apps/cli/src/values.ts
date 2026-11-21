import type {
  DistributedEnvironmentManifest,
  DistributedEnvironmentMetaStatement,
  DistributedVariableMetaStatement,
  RecipientDek,
  SchemaPolicy,
} from "@maruhi/api-schema";
import { type EnvironmentId, type VariableId } from "@maruhi/core";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { resyncExtended, type VerifiedProject } from "./chain-sync.ts";
import { checkCheckpointIntegrity } from "./checkpoint-integrity.ts";
import { cliError, type CliError, evidenceError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type {
  FloorHandle,
  VerifiedEnvironmentStatement,
  VerifiedMetaEvidence,
  VerifiedPullSnapshot,
  VerifiedTombstone,
  VerifiedVariableStatement,
} from "./floor-check.ts";
import type { ManifestFloor } from "./floor.ts";
import {
  type ManifestDigestEntry,
  type VerifiedManifest,
  verifyDistributedManifest,
} from "./manifest.ts";
import { enforceFloor, enforceMetadataFloor } from "./values-floor.ts";
import {
  checkVerifiedNames,
  type PullWire,
  type VerifiedPulledValue,
  verifyActiveVariables,
  verifyDeclaredStatements,
  verifyDeletedStatements,
  verifyEnvironmentStatement,
  verifyVariableStatements,
  type VerifyOutcome,
} from "./values-verify.ts";

export interface VerifiedEnvironmentPull {
  readonly verified: VerifiedProject;
  readonly variables: readonly VerifiedPulledValue[];
  readonly declared: readonly VerifiedVariableStatement[];
  readonly tombstones: readonly VerifiedTombstone[];
  readonly environment: VerifiedMetaEvidence;
  readonly manifest: VerifiedManifest;
  readonly deks: readonly RecipientDek[];
  readonly warnings: readonly string[];
}

type StageResult<T> = { readonly kind: "ok"; readonly value: T } | { readonly kind: "future" };

const verifyStage = Effect.fn("values.verifyStage")(function* <T>(
  run: () => Promise<VerifyOutcome<T>>,
  description: string,
): Effect.fn.Return<StageResult<T>, CliError> {
  const outcome = yield* Effect.tryPromise({
    try: run,
    catch: () => cliError(`${description} failed to run (crypto error)`),
  });
  if (outcome.kind === "rejected") {
    return yield* Effect.fail(
      outcome.evidence ? evidenceError(outcome.message) : cliError(outcome.message),
    );
  }
  return outcome.kind === "future"
    ? ({ kind: "future" } as const)
    : ({ kind: "ok", value: outcome.value } as const);
});

function verifyManifestStage(input: {
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly manifest: DistributedEnvironmentManifest;
  readonly entries: readonly ManifestDigestEntry[];
  readonly environment: VerifiedMetaEvidence;
  readonly floorManifest: ManifestFloor | null;
}): Effect.Effect<StageResult<VerifiedManifest>, CliError> {
  return verifyStage(
    () =>
      verifyDistributedManifest({
        verified: input.verified,
        environmentId: input.environmentId,
        manifest: input.manifest,
        entries: input.entries,
        envMeta: {
          metaVersion: input.environment.metaVersion,
          sigHashHex: input.environment.metaSigHashHex,
        },
        floorManifest: input.floorManifest,
      }).then((outcome) =>
        outcome.kind === "rejected" ? { ...outcome, evidence: true } : outcome,
      ),
    "Environment-manifest verification",
  );
}

const verifyAllCommon = Effect.fn("values.verifyAllCommon")(function* <
  T extends { readonly variableId: VariableId; readonly name: string },
>(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  pull: {
    readonly statement: DistributedEnvironmentMetaStatement;
    readonly deletedVariables: readonly DistributedVariableMetaStatement[];
    readonly declaredVariables?: readonly DistributedVariableMetaStatement[] | undefined;
    readonly manifest: DistributedEnvironmentManifest;
  },
  verifyActives: () => Promise<
    VerifyOutcome<{ readonly values: readonly T[]; readonly ids: Set<string> }>
  >,
  digestEntryOf: (value: T) => ManifestDigestEntry,
  floorManifest: ManifestFloor | null,
): Effect.fn.Return<
  | {
      readonly kind: "ok";
      readonly environment: VerifiedEnvironmentStatement;
      readonly variables: readonly T[];
      readonly declared: readonly VerifiedVariableStatement[];
      readonly tombstones: readonly VerifiedTombstone[];
      readonly manifest: VerifiedManifest;
      readonly warnings: readonly string[];
    }
  | { readonly kind: "future" },
  CliError
> {
  const environment = yield* verifyStage(
    () => verifyEnvironmentStatement(verified, environmentId, pull.statement),
    "Environment-statement verification",
  );
  if (environment.kind === "future") {
    return { kind: "future" } as const;
  }
  const actives = yield* verifyStage(
    verifyActives,
    "Variable-statement / value-signature verification",
  );
  if (actives.kind === "future") {
    return { kind: "future" } as const;
  }
  const declared = yield* verifyStage(
    () =>
      verifyDeclaredStatements(
        verified,
        environmentId,
        pull.declaredVariables ?? [],
        actives.value.ids,
      ),
    "Declared-variable-statement verification",
  );
  if (declared.kind === "future") {
    return { kind: "future" } as const;
  }
  const liveIds = new Set([...actives.value.ids, ...declared.value.ids]);
  const deleted = yield* verifyStage(
    () => verifyDeletedStatements(verified, environmentId, pull.deletedVariables, liveIds),
    "Deleted-variable-statement verification",
  );
  if (deleted.kind === "future") {
    return { kind: "future" } as const;
  }
  const warnings: string[] = [];
  const nameFailure = checkVerifiedNames(
    [...actives.value.values, ...declared.value.values],
    warnings,
  );
  if (nameFailure !== null) {
    return yield* Effect.fail(cliError(nameFailure));
  }
  const manifest = yield* verifyManifestStage({
    verified,
    environmentId,
    manifest: pull.manifest,
    entries: [
      ...actives.value.values.map(digestEntryOf),
      ...declared.value.values.map((statement) => ({
        variableId: statement.variableId,
        status: "declared" as const,
        metaVersion: statement.metaVersion,
        metaSigHashHex: statement.metaSigHashHex,
      })),
      ...deleted.value.map((tombstone) => ({
        variableId: tombstone.variableId,
        status: "deleted" as const,
        metaVersion: tombstone.metaVersion,
        metaSigHashHex: tombstone.metaSigHashHex,
      })),
    ],
    environment: environment.value,
    floorManifest,
  });
  if (manifest.kind === "future") {
    return { kind: "future" } as const;
  }
  return {
    kind: "ok",
    environment: environment.value,
    variables: actives.value.values,
    declared: declared.value.values,
    tombstones: deleted.value,
    manifest: manifest.value,
    warnings,
  } as const;
});

const verifyAll = Effect.fn("values.verifyAll")(function* (
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  pull: PullWire,
  floorManifest: ManifestFloor | null,
  fetchedAtHeadSeq: number,
): Effect.fn.Return<
  | {
      readonly kind: "ok";
      readonly snapshot: VerifiedPullSnapshot;
      readonly warnings: readonly string[];
    }
  | { readonly kind: "future" },
  CliError
> {
  const result = yield* verifyAllCommon(
    verified,
    environmentId,
    pull,
    () => verifyActiveVariables(verified, environmentId, pull.variables),
    (value) => ({
      variableId: value.variableId,
      status: "active" as const,
      metaVersion: value.metaVersion,
      metaSigHashHex: value.metaSignedBytesHashHex,
    }),
    floorManifest,
  );
  if (result.kind === "future") {
    return { kind: "future" } as const;
  }
  const checkpoint = yield* Effect.tryPromise({
    try: () =>
      checkCheckpointIntegrity({
        history: verified.history,
        environmentId,
        snapshot: pull.checkpointSnapshot,
        variables: result.variables,
        tombstoneIds: new Set(result.tombstones.map((tombstone) => tombstone.variableId)),
        fetchedAtHeadSeq,
      }),
    catch: () => cliError("Checkpoint-integrity verification failed to run (crypto error)"),
  });
  if (checkpoint.kind === "rejected") {
    return yield* Effect.fail(
      checkpoint.evidence ? evidenceError(checkpoint.message) : cliError(checkpoint.message),
    );
  }
  if (checkpoint.kind === "future") {
    return { kind: "future" } as const;
  }
  return {
    kind: "ok",
    snapshot: {
      environment: result.environment,
      variables: result.variables,
      declared: result.declared,
      tombstones: result.tombstones,
      manifest: result.manifest,
    },
    warnings: result.warnings,
  } as const;
});

export const pullWithBoundedResync = Effect.fn("values.pullWithBoundedResync")(function* <
  TWire,
  TVerified,
>(input: {
  readonly verified: VerifiedProject;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly fetch: Effect.Effect<TWire, CliError>;
  readonly verify: (
    view: VerifiedProject,
    wire: TWire,
  ) => Effect.Effect<
    { readonly kind: "ok"; readonly value: TVerified } | { readonly kind: "future" },
    CliError
  >;
  readonly accept: (view: VerifiedProject, value: TVerified) => Effect.Effect<void, CliError>;
  readonly divergedMessage: string;
}): Effect.fn.Return<
  { readonly view: VerifiedProject; readonly wire: TWire; readonly value: TVerified },
  CliError
> {
  const wire = yield* input.fetch;
  const first = yield* input.verify(input.verified, wire);
  if (first.kind === "ok") {
    yield* input.accept(input.verified, first.value);
    return { view: input.verified, wire, value: first.value };
  }
  const advanced = yield* resyncExtended(input.resync, input.verified);
  const second = yield* input.verify(advanced, wire);
  if (second.kind === "ok") {
    yield* input.accept(advanced, second.value);
    return { view: advanced, wire, value: second.value };
  }
  return yield* Effect.fail(evidenceError(input.divergedMessage));
});

export function pullVerifiedEnvironment(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
}): Effect.Effect<VerifiedEnvironmentPull, CliError> {
  return Effect.map(
    pullWithBoundedResync({
      verified: input.verified,
      resync: input.resync,
      fetch: input.client.variables
        .pull({
          params: { projectId: input.verified.projectId, environmentId: input.environmentId },
        })
        .pipe(Effect.mapError(toCliError)),
      verify: (view, wire) =>
        verifyAll(
          view,
          input.environmentId,
          wire,
          input.floor.current()?.manifest ?? null,
          input.verified.state.headSeq,
        ).pipe(
          Effect.map((result) =>
            result.kind === "future"
              ? result
              : ({
                  kind: "ok",
                  value: { snapshot: result.snapshot, warnings: result.warnings },
                } as const),
          ),
        ),
      accept: (view, value) =>
        enforceFloor({
          floor: input.floor,
          baselineView: input.verified,
          commitView: view,
          environmentId: input.environmentId,
          snapshot: value.snapshot,
        }),
      divergedMessage:
        "A value, statement or checkpoint snapshot bound to a chain position that still does not exist on the chain after a re-sync was served (evidence of chain divergence or forgery)",
    }),
    ({ view, wire, value }) => ({
      verified: view,
      variables: value.snapshot.variables,
      declared: value.snapshot.declared,
      tombstones: value.snapshot.tombstones,
      environment: value.snapshot.environment,
      manifest: value.snapshot.manifest,
      deks: wire.deks,
      warnings: value.warnings,
    }),
  );
}

export const verifyLeaseDistribution = Effect.fn("values.verifyLeaseDistribution")(
  function* (input: {
    readonly verified: VerifiedProject;
    readonly environmentId: EnvironmentId;
    readonly wire: PullWire;
  }): Effect.fn.Return<
    {
      readonly variables: readonly VerifiedPulledValue[];
      readonly declared: readonly VerifiedVariableStatement[];
      readonly warnings: readonly string[];
    },
    CliError
  > {
    const result = yield* verifyAll(
      input.verified,
      input.environmentId,
      input.wire,
      null,
      input.verified.state.headSeq,
    );
    if (result.kind === "future") {
      return yield* Effect.fail(
        cliError(
          "A value, statement or checkpoint snapshot in the lease response is bound to a chain position beyond the chain included in the same response (the response contradicts itself)",
        ),
      );
    }
    const warnings =
      input.verified.history.latestCheckpointFor(input.environmentId) === undefined
        ? [
            ...result.warnings,
            `No checkpoint on the verified chain covers environment ${input.environmentId}, so checkpoint integrity (rollback and stale-epoch injection detection — CRYPTO_SPEC §6.3) does not protect this response. A project member should issue one with: \`maruhi project checkpoint\``,
          ]
        : result.warnings;
    return {
      variables: result.snapshot.variables,
      declared: result.snapshot.declared,
      warnings,
    };
  },
);

export interface VerifiedEnvironmentMetadata {
  readonly verified: VerifiedProject;
  readonly variables: readonly VerifiedVariableStatement[];
  readonly tombstones: readonly VerifiedTombstone[];
  readonly environment: VerifiedEnvironmentStatement;
  readonly manifest: VerifiedManifest;
  readonly advisorySchemaPolicy: SchemaPolicy;
  readonly warnings: readonly string[];
}

export interface ManifestIssueBase {
  readonly previous: {
    readonly manifestVersion: number;
    readonly signedBytesHashHex: string;
  };
  readonly entries: readonly ManifestDigestEntry[];
  readonly envMeta: { readonly metaVersion: number; readonly sigHashHex: string };
}

export function manifestIssueBaseOf(metadata: VerifiedEnvironmentMetadata): ManifestIssueBase {
  return {
    previous: {
      manifestVersion: metadata.manifest.manifestVersion,
      signedBytesHashHex: metadata.manifest.signedBytesHashHex,
    },
    entries: [
      ...metadata.variables.map((statement) => ({
        variableId: statement.variableId,
        status: statement.status,
        metaVersion: statement.metaVersion,
        metaSigHashHex: statement.metaSigHashHex,
      })),
      ...metadata.tombstones.map((tombstone) => ({
        variableId: tombstone.variableId,
        status: "deleted" as const,
        metaVersion: tombstone.metaVersion,
        metaSigHashHex: tombstone.metaSigHashHex,
      })),
    ],
    envMeta: {
      metaVersion: metadata.environment.metaVersion,
      sigHashHex: metadata.environment.metaSigHashHex,
    },
  };
}

interface MetadataPullWire {
  readonly statement: DistributedEnvironmentMetaStatement;
  readonly variables: readonly DistributedVariableMetaStatement[];
  readonly deletedVariables: readonly DistributedVariableMetaStatement[];
  readonly manifest: DistributedEnvironmentManifest;
  readonly schemaPolicy: SchemaPolicy;
}

interface VerifiedMetadataValue {
  readonly environment: VerifiedEnvironmentStatement;
  readonly variables: readonly VerifiedVariableStatement[];
  readonly tombstones: readonly VerifiedTombstone[];
  readonly manifest: VerifiedManifest;
  readonly warnings: readonly string[];
}

function verifyAllMetadata(
  verified: VerifiedProject,
  environmentId: EnvironmentId,
  pull: MetadataPullWire,
  floorManifest: ManifestFloor | null,
): Effect.Effect<
  | {
      readonly kind: "ok";
      readonly environment: VerifiedEnvironmentStatement;
      readonly variables: readonly VerifiedVariableStatement[];
      readonly tombstones: readonly VerifiedTombstone[];
      readonly manifest: VerifiedManifest;
      readonly warnings: readonly string[];
    }
  | { readonly kind: "future" },
  CliError
> {
  return verifyAllCommon(
    verified,
    environmentId,
    { ...pull, declaredVariables: [] },
    () => verifyVariableStatements(verified, environmentId, pull.variables),
    (statement) => ({
      variableId: statement.variableId,
      status: statement.status,
      metaVersion: statement.metaVersion,
      metaSigHashHex: statement.metaSigHashHex,
    }),
    floorManifest,
  );
}

export function pullVerifiedEnvironmentMetadata(input: {
  readonly client: MaruhiClient;
  readonly verified: VerifiedProject;
  readonly environmentId: EnvironmentId;
  readonly resync: Effect.Effect<VerifiedProject, CliError>;
  readonly floor: FloorHandle;
}): Effect.Effect<VerifiedEnvironmentMetadata, CliError> {
  return Effect.map(
    pullWithBoundedResync({
      verified: input.verified,
      resync: input.resync,
      fetch: input.client.variables
        .pullMetadata({
          params: { projectId: input.verified.projectId, environmentId: input.environmentId },
        })
        .pipe(Effect.mapError(toCliError)),
      verify: (view, wire) =>
        verifyAllMetadata(
          view,
          input.environmentId,
          wire,
          input.floor.current()?.manifest ?? null,
        ).pipe(
          Effect.flatMap(
            (
              result,
            ): Effect.Effect<
              | { readonly kind: "ok"; readonly value: VerifiedMetadataValue }
              | { readonly kind: "future" },
              CliError
            > => {
              if (result.kind === "future") {
                return Effect.succeed({ kind: "future" as const });
              }
              return Effect.succeed({
                kind: "ok" as const,
                value: {
                  environment: result.environment,
                  variables: result.variables,
                  tombstones: result.tombstones,
                  manifest: result.manifest,
                  warnings: result.warnings,
                },
              });
            },
          ),
        ),
      accept: (view, value) =>
        enforceMetadataFloor({
          floor: input.floor,
          verified: view,
          environmentId: input.environmentId,
          environment: value.environment,
          variables: value.variables,
          tombstones: value.tombstones,
          manifest: value.manifest,
        }),
      divergedMessage:
        "A statement bound to a head that still does not exist on the chain after a re-sync was served (evidence of chain divergence or forgery)",
    }),
    ({ view, wire, value }) => ({
      verified: view,
      variables: value.variables,
      tombstones: value.tombstones,
      environment: value.environment,
      manifest: value.manifest,
      advisorySchemaPolicy: wire.schemaPolicy,
      warnings: value.warnings,
    }),
  );
}
