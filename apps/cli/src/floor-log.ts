import { join } from "node:path";

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import { decodeProjectId, isProjectId, type ProjectId, type EnvironmentId } from "@maruhi/core";
import { Data, Effect, FileSystem, type PlatformError, Predicate, Schema } from "effect";
import { Hex } from "effect/encoding";

import { cliError, type CliError } from "./errors.ts";
import { formatFloorConflicts } from "./floor-evidence.ts";
import { decodeChainHead, type FloorLogRecord } from "./floor-log-decode.ts";
import { type FoldOutcome, foldRecords } from "./floor-log-fold.ts";
import {
  type AttestationEvidenceRecord,
  emptyEnvironmentFloor,
  type EnvironmentFloor,
  type FloorIntent,
  type FloorIntentInput,
  type FloorLoadResult,
  floorRecordGet,
  type FloorStoreShape,
  type ManifestCommit,
  type MetadataCommit,
  type ProjectFloor,
  type PullCommit,
  type PushCommit,
} from "./floor.ts";
import { readJsonFile, writeJsonFileAtomic } from "./json-record.ts";

const DEFAULT_COMPACTION_THRESHOLD = 256;

const MAX_APPEND_WRITE_ATTEMPTS = 3;

function isFileMissingError(error: PlatformError.PlatformError): boolean {
  return Predicate.isTagged("NotFound")(error.reason);
}

class ShortWriteError extends Data.TaggedError("ShortWrite")<{
  readonly logName: string;
  readonly bytesWritten: number;
  readonly payloadBytes: number;
}> {}

const appendAll = (
  handle: FileSystem.File,
  payload: Uint8Array,
  logName: string,
): Effect.Effect<void, PlatformError.PlatformError | ShortWriteError> =>
  handle.write(payload).pipe(
    Effect.flatMap((bytesWritten) =>
      bytesWritten === payload.length
        ? Effect.void
        : Effect.fail(
            new ShortWriteError({
              logName,
              bytesWritten,
              payloadBytes: payload.length,
            }),
          ),
    ),
    Effect.retry({
      times: MAX_APPEND_WRITE_ATTEMPTS - 1,
      while: (error) => Predicate.isTagged(error, "ShortWrite") && error.bytesWritten > 0,
    }),
    Effect.andThen(handle.sync),
  );

function encodeRecord(record: FloorLogRecord): string {
  return `${JSON.stringify(record)}\n`;
}

function randomIntentId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return Hex.encode(bytes);
}

function environmentOf(floor: ProjectFloor, environmentId: EnvironmentId): EnvironmentFloor {
  return floorRecordGet(floor.environments, environmentId) ?? emptyEnvironmentFloor();
}

export interface FileFloorStoreOptions {
  readonly compactionThreshold?: number;
}

const mapErrorTo =
  (message: (projectId: ProjectId) => string) =>
  <A, E, R>(effect: Effect.Effect<A, E, R>, projectId: ProjectId): Effect.Effect<A, CliError, R> =>
    effect.pipe(Effect.mapError(() => cliError(message(projectId))));

const AttestedHeadFileSchema = Schema.Struct({
  v: Schema.Literal(1),
  head: Schema.Unknown,
});

export function makeFileFloorStore(dir: string, options?: FileFloorStoreOptions): FloorStoreShape {
  const compactionThreshold = options?.compactionThreshold ?? DEFAULT_COMPACTION_THRESHOLD;

  const pathOf = (projectId: ProjectId): string => {
    if (!isProjectId(projectId)) {
      throw new Error(`invalid project id for floor path: ${projectId}`);
    }
    return join(dir, `${projectId}.jsonl`);
  };
  const logPathOf = (projectId: ProjectId): Effect.Effect<string, CliError> =>
    Effect.try({
      try: () => pathOf(projectId),
      catch: () =>
        cliError(
          `Cannot write the local floor log: ${join(dir, `${projectId}.jsonl`)} (aborting because rollback detection cannot continue)`,
        ),
    });

  const appendPayload = (
    path: string,
    payload: Uint8Array,
    logName: string,
  ): Effect.Effect<void, PlatformError.PlatformError | ShortWriteError, FileSystem.FileSystem> =>
    Effect.gen(function* () {
      const fs = yield* FileSystem.FileSystem;
      yield* fs.makeDirectory(dir, { recursive: true, mode: 0o700 });
      yield* Effect.scoped(
        Effect.gen(function* () {
          const handle = yield* fs.open(path, { flag: "a", mode: 0o600 });
          yield* appendAll(handle, payload, logName);
        }),
      );
    });

  const appendRecords = (
    projectId: ProjectId,
    records: readonly FloorLogRecord[],
  ): Effect.Effect<
    void,
    CliError | PlatformError.PlatformError | ShortWriteError,
    FileSystem.FileSystem
  > =>
    Effect.gen(function* () {
      const path = yield* logPathOf(projectId);
      yield* appendPayload(
        path,
        Buffer.from(`\n${records.map(encodeRecord).join("")}`, "utf8"),
        "floor log",
      );
    });

  const readAndFold = (
    projectId: ProjectId,
  ): Effect.Effect<FoldOutcome, CliError | PlatformError.PlatformError, FileSystem.FileSystem> =>
    Effect.gen(function* () {
      const fs = yield* FileSystem.FileSystem;
      const path = yield* logPathOf(projectId);
      const raw = yield* fs.readFileString(path, "utf8");
      return foldRecords(raw.split("\n"));
    });

  const mutate = (
    projectId: ProjectId,
    records: readonly FloorLogRecord[],
  ): Effect.Effect<ProjectFloor, CliError> =>
    Effect.gen(function* () {
      yield* appendRecords(projectId, records);
      let outcome = yield* readAndFold(projectId);
      if (outcome.recordsSinceSnapshot > compactionThreshold) {
        yield* appendRecords(projectId, [
          {
            r: "snapshot",
            folded: outcome.decodedRecords,
            state: {
              chainHead: outcome.floor.chainHead,
              environments: outcome.floor.environments,
              conflicts: outcome.floor.conflicts,
              intents: outcome.floor.intents,
            },
          },
        ]);
        outcome = yield* readAndFold(projectId);
      }
      return outcome.floor;
    }).pipe(
      Effect.mapError(() =>
        cliError(
          `Cannot write the local floor log: ${join(dir, `${projectId}.jsonl`)} (aborting because rollback detection cannot continue)`,
        ),
      ),
      Effect.flatMap((floor) =>
        floor.conflicts.length > 0
          ? Effect.fail(cliError(formatFloorConflicts(projectId, floor.conflicts)))
          : Effect.succeed(floor),
      ),
      Effect.provide(BunFileSystem.layer),
    );

  const attestedPathOf = (projectId: ProjectId): string => {
    if (!isProjectId(projectId)) {
      throw new Error(`invalid project id for attested-head path: ${projectId}`);
    }
    return join(dir, `${projectId}.attested.json`);
  };

  const evidencePathOf = (projectId: ProjectId): string => {
    if (!isProjectId(projectId)) {
      throw new Error(`invalid project id for attestation-evidence path: ${projectId}`);
    }
    return join(dir, `${projectId}.attestation-evidence.jsonl`);
  };

  const appendJsonLine = (
    path: string,
    value: AttestationEvidenceRecord,
  ): Effect.Effect<void, PlatformError.PlatformError | ShortWriteError, FileSystem.FileSystem> =>
    appendPayload(
      path,
      Buffer.from(`\n${JSON.stringify(value)}\n`, "utf8"),
      "attestation-evidence log",
    );

  return {
    load: Effect.fn("floor-log.load")(
      function* (projectId) {
        const fs = yield* FileSystem.FileSystem;
        const path = yield* Effect.try({
          try: () => pathOf(projectId),
          catch: () =>
            cliError(`Cannot read the local floor log: ${join(dir, `${projectId}.jsonl`)}`),
        });
        const raw = yield* fs
          .readFileString(path, "utf8")
          .pipe(
            Effect.catch((error) =>
              isFileMissingError(error) ? Effect.succeed(null) : Effect.fail(error),
            ),
          );
        if (raw === null) {
          return { floor: null, state: "missing", droppedRecords: 0 } satisfies FloorLoadResult;
        }
        const outcome = foldRecords(raw.split("\n"));
        if (outcome.decodedRecords === 0) {
          if (raw.trim() !== "") {
            return {
              floor: null,
              state: "corrupt",
              droppedRecords: outcome.droppedLines,
            } satisfies FloorLoadResult;
          }
          return { floor: null, state: "missing", droppedRecords: 0 } satisfies FloorLoadResult;
        }
        return {
          floor: outcome.floor,
          state: "loaded",
          droppedRecords: outcome.droppedLines,
        } satisfies FloorLoadResult;
      },
      mapErrorTo(
        (projectId) => `Cannot read the local floor log: ${join(dir, `${projectId}.jsonl`)}`,
      ),
      Effect.provide(BunFileSystem.layer),
    ),
    commitHead: (projectId, head) => Effect.asVoid(mutate(projectId, [{ r: "head", head }])),
    commitPull: (projectId, commit: PullCommit) =>
      mutate(projectId, [
        {
          r: "pull",
          head: commit.chainHead,
          environmentId: commit.environmentId,
          environment: commit.environment,
        },
      ]).pipe(Effect.map((floor) => environmentOf(floor, commit.environmentId))),
    commitPush: (projectId, commit: PushCommit) =>
      mutate(projectId, [
        {
          r: "push",
          head: commit.chainHead,
          environmentId: commit.environmentId,
          variableId: commit.variableId,
          variable: commit.variable,
        },
      ]).pipe(Effect.map((floor) => environmentOf(floor, commit.environmentId))),
    commitMetadata: (projectId, commit: MetadataCommit) =>
      mutate(projectId, [
        {
          r: "meta",
          head: commit.chainHead,
          environmentId: commit.environmentId,
          observedEpoch: commit.observedEpoch,
          metaVersion: commit.metaVersion,
          metaSigHashHex: commit.metaSigHashHex,
          manifest: commit.manifest,
        },
      ]).pipe(Effect.map((floor) => environmentOf(floor, commit.environmentId))),
    commitManifest: (projectId, commit: ManifestCommit) =>
      mutate(projectId, [
        {
          r: "manifest",
          head: commit.chainHead,
          environmentId: commit.environmentId,
          manifest: commit.manifest,
        },
      ]).pipe(Effect.map((floor) => environmentOf(floor, commit.environmentId))),
    appendIntent: (projectId, input: FloorIntentInput) => {
      const intent: FloorIntent = { id: randomIntentId(), ...input };
      return mutate(projectId, [{ r: "intent", intent }]).pipe(Effect.map(() => intent.id));
    },
    resolveIntent: (projectId, intentId, outcome) =>
      Effect.asVoid(
        appendRecords(projectId, [{ r: "resolution", intentId, outcome }]).pipe(
          Effect.mapError(() =>
            cliError(
              `Cannot write the local floor log: ${join(dir, `${projectId}.jsonl`)} (aborting because rollback detection cannot continue)`,
            ),
          ),
          Effect.provide(BunFileSystem.layer),
        ),
      ),
    listProjectIds: Effect.fn("floor-log.listProjectIds")(
      function* () {
        const fs = yield* FileSystem.FileSystem;
        const names = yield* fs
          .readDirectory(dir)
          .pipe(
            Effect.catch((error) =>
              isFileMissingError(error) ? Effect.succeed([] as string[]) : Effect.fail(error),
            ),
          );
        const ids = new Set<ProjectId>();
        for (const name of names) {
          const match = /^(.+)\.jsonl$/.exec(name);
          if (match?.[1] !== undefined && isProjectId(match[1])) {
            ids.add(decodeProjectId(match[1]));
          }
        }
        return [...ids].toSorted();
      },
      Effect.mapError(() => cliError(`Cannot list the local floor directory: ${dir}`)),
      Effect.provide(BunFileSystem.layer),
    ),
    loadAttestedHead: Effect.fn("floor-log.loadAttestedHead")(
      function* (projectId) {
        const path = yield* Effect.try({
          try: () => attestedPathOf(projectId),
          catch: () =>
            cliError(
              `Cannot read the attested-head file: ${join(dir, `${projectId}.attested.json`)}`,
            ),
        });
        const read = yield* readJsonFile(path, AttestedHeadFileSchema);
        return read.state === "loaded" ? decodeChainHead(read.file.head) : null;
      },
      mapErrorTo(
        (projectId) =>
          `Cannot read the attested-head file: ${join(dir, `${projectId}.attested.json`)}`,
      ),
      Effect.provide(BunFileSystem.layer),
    ),
    saveAttestedHead: Effect.fn("floor-log.saveAttestedHead")(
      function* (projectId, head) {
        const path = yield* Effect.try({
          try: () => attestedPathOf(projectId),
          catch: () =>
            cliError(
              `Cannot write the attested-head file: ${join(dir, `${projectId}.attested.json`)}`,
            ),
        });
        yield* writeJsonFileAtomic(path, AttestedHeadFileSchema, { v: 1, head });
      },
      mapErrorTo(
        (projectId) =>
          `Cannot write the attested-head file: ${join(dir, `${projectId}.attested.json`)}`,
      ),
      Effect.provide(BunFileSystem.layer),
    ),
    appendAttestationEvidence: Effect.fn("floor-log.appendAttestationEvidence")(
      function* (projectId, evidence) {
        const path = yield* Effect.try({
          try: () => evidencePathOf(projectId),
          catch: () =>
            cliError(
              `Cannot write the attestation-evidence log: ${join(dir, `${projectId}.attestation-evidence.jsonl`)}`,
            ),
        });
        yield* appendJsonLine(path, evidence);
        return path;
      },
      mapErrorTo(
        (projectId) =>
          `Cannot write the attestation-evidence log: ${join(
            dir,
            `${projectId}.attestation-evidence.jsonl`,
          )}`,
      ),
      Effect.provide(BunFileSystem.layer),
    ),
  };
}
