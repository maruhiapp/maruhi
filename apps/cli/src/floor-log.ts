// The local floor's storage form: an append-only observation log + fold
// (CRYPTO_SPEC §6.3's 3-E / 3-E′ / 3-F).
//
// - The floor file is an "append-only log of verified observations (one
//   observation = one JSONL line)", and the floor is **derived** as the
//   join produced by folding the log. An overwrite-update storage form
//   (read, merge, write back) is not used — observations of concurrent
//   processes both remain in the log, and a same-coordinate conflict
//   surfaces as a typed conflict at fold time (**evidence loss via
//   overwrite goes from "forbidden" to "inexpressible"**). In M1 there
//   is no inter-process lock at all (appends only)
// - Appends go only through append mode (O_APPEND equivalent) and **wait
//   for fsync-equivalent durability** (3-E′ — the "record" standard of
//   journal-before-release / before-send)
// - Corrupt records (torn writes from a crash or power loss) are ignored
//   by fold (self-healing). Because every append is **prefixed** with a
//   newline, a torn line never corrupts later records (no tail-end
//   check — see appendRecords's JSDoc)
// - Compaction only happens by **appending a snapshot record** holding
//   "the current fold result + the end position of the folded prefix"
//   (the trigger is exceeding a threshold of the relative amount
//   accumulated after the latest snapshot record). M1 never rewrites,
//   truncates, or physically reclaims (to be designed together with
//   M2's checkpoint-baseline linking). The evidence of a same-coordinate
//   conflict is not lost by being folded into a snapshot
// - intent / resolution records (3-F) are a separate class that does not
//   enter the join's lattice — fold surfaces an unresolved intent as
//   "needs reconciliation"

import { join } from "node:path";

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import { isProjectId } from "@maruhi/core";
import { Data, Effect, FileSystem, type PlatformError, Predicate, Schema } from "effect";

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

/**
 * The compaction trigger: a threshold on the number of records
 * accumulated after the latest snapshot record (a relative amount — a
 * total-file-size basis is not used because once exceeded it holds
 * forever). Bounding the fold cost is carried by this relative basis
 * itself.
 */
const DEFAULT_COMPACTION_THRESHOLD = 256;

/** The cap on full-length rewrite retries of one logical append (short write — appendAll). */
const MAX_APPEND_WRITE_ATTEMPTS = 3;

// ---- File store ----

function isFileMissingError(error: PlatformError.PlatformError): boolean {
  return Predicate.isTagged("NotFound")(error.reason);
}

/**
 * A logical append that stayed unwritten past the full-length rewrite
 * budget (appendAll — including a 0-byte write).
 */
class ShortWriteError extends Data.TaggedError("ShortWrite")<{
  readonly logName: string;
  readonly bytesWritten: number;
  readonly payloadBytes: number;
}> {}

/**
 * Writes payload to an O_APPEND-opened handle as one logical append and
 * waits through fsync (the physical discipline for appends to the
 * floor log / evidence log).
 *
 * One logical append = one write syscall (the unit O_APPEND's atomicity
 * covers). On a short write, **do not splice on the remainder**: a second
 * splicing write would interleave with another process's append, and one
 * record would split into two invalid fragments lost silently (a shape
 * that must never return success). Since readers discard the fragment as
 * a torn line already isolated by newline-prefixing, rewrite the
 * **whole** payload from the start. If it runs out still unwritten
 * (including a 0-byte write), fail.
 */
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
    // Retry only a non-zero short write, within the full-length rewrite
    // budget: a 0-byte write fails immediately, and the last attempt's
    // ShortWriteError propagates when the budget runs out
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
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** The commit functions' return value: the environment's floor from the folded floor (bottom if unobserved). */
function environmentOf(floor: ProjectFloor, environmentId: string): EnvironmentFloor {
  return floorRecordGet(floor.environments, environmentId) ?? emptyEnvironmentFloor();
}

export interface FileFloorStoreOptions {
  /** The compaction trigger (record count after the latest snapshot). A test override. */
  readonly compactionThreshold?: number;
}

/**
 * `Effect.fn` runs each pipeable as `p(effect, ...callArgs)`: binding the
 * project id here keeps each refusal message naming the project's file.
 */
const mapErrorTo =
  (message: (projectId: string) => string) =>
  <A, E, R>(effect: Effect.Effect<A, E, R>, projectId: string): Effect.Effect<A, CliError, R> =>
    effect.pipe(Effect.mapError(() => cliError(message(projectId))));

/**
 * The attested-head file's shape: `{ v: 1, head }`. `v` is the
 * format-version marker (a file without it, or with another version, reads
 * as corrupt). `head` is decodable-checked by decodeChainHead, not the
 * schema.
 */
const AttestedHeadFileSchema = Schema.Struct({
  v: Schema.Literal(1),
  head: Schema.Unknown,
});

/** File-backed append-only floor store rooted at `dir` (production and tests share this). */
export function makeFileFloorStore(dir: string, options?: FileFloorStoreOptions): FloorStoreShape {
  const compactionThreshold = options?.compactionThreshold ?? DEFAULT_COMPACTION_THRESHOLD;

  const pathOf = (projectId: string): string => {
    // projectId is supposed to be a genesis hash (hex-64), but the form
    // is enforced before it goes into a file name (prevents untrusted
    // strings from mixing into path assembly)
    if (!isProjectId(projectId)) {
      throw new Error(`invalid project id for floor path: ${projectId}`);
    }
    return join(dir, `${projectId}.jsonl`);
  };
  /**
   * Appending (O_APPEND equivalent) + fsync-equivalent durability
   * (3-E′).
   *
   * Every write is **prefixed** with a newline: even if a concurrent
   * process's torn line (an unfinished write without a newline) landed
   * right before, our record is always isolated as a fresh line (fold
   * ignores empty lines). The "read the tail byte to decide" shape is not
   * used because it races a torn line slipping in between the check and
   * the O_APPEND write (once interrupted, our complete record would be
   * concatenated onto that line and lost, silently breaking
   * journal-before-release). write loops until every byte is written,
   * guarding against short writes (fsync is the durability standard —
   * 3-E′).
   */
  /**
   * `pathOf` lifted into the effect channel: an invalid id (a guard for
   * paths assembled from an untrusted string) surfaces as the write
   * failure, matching the envelope a thrown Error took through
   * `tryPromise` before.
   */
  const logPathOf = (projectId: string): Effect.Effect<string, CliError> =>
    Effect.try({
      try: () => pathOf(projectId),
      catch: () =>
        cliError(
          `Cannot write the local floor log: ${join(dir, `${projectId}.jsonl`)} (aborting because rollback detection cannot continue)`,
        ),
    });

  /**
   * mkdir-if-missing → open("a") → appendAll — the shared physical
   * append sequence for the floor log and the evidence log (the file
   * is created lazily on first append).
   */
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
    projectId: string,
    records: readonly FloorLogRecord[],
  ): Effect.Effect<
    void,
    CliError | PlatformError.PlatformError | ShortWriteError,
    FileSystem.FileSystem
  > =>
    Effect.gen(function* () {
      const path = yield* logPathOf(projectId);
      // If it runs out still unwritten it fails (the caller never
      // treats it as "persisted"). Duplicate records are harmless
      // via the join's idempotence
      yield* appendPayload(
        path,
        Buffer.from(`\n${records.map(encodeRecord).join("")}`, "utf8"),
        "floor log",
      );
    });

  const readAndFold = (
    projectId: string,
  ): Effect.Effect<FoldOutcome, CliError | PlatformError.PlatformError, FileSystem.FileSystem> =>
    Effect.gen(function* () {
      const fs = yield* FileSystem.FileSystem;
      const path = yield* logPathOf(projectId);
      const raw = yield* fs.readFileString(path, "utf8");
      return foldRecords(raw.split("\n"));
    });

  /** Append → fold. If fold produced a conflict it is a typed error (the evidence remains in the log). */
  const mutate = (
    projectId: string,
    records: readonly FloorLogRecord[],
  ): Effect.Effect<ProjectFloor, CliError> =>
    Effect.gen(function* () {
      yield* appendRecords(projectId, records);
      let outcome = yield* readAndFold(projectId);
      if (outcome.recordsSinceSnapshot > compactionThreshold) {
        // Compaction = only appending a snapshot record (never a
        // rewrite). Two concurrent snapshots are harmless (fold bases
        // on the latest one, and the position basis + join idempotence
        // keep even a double fold correct)
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

  const attestedPathOf = (projectId: string): string => {
    if (!isProjectId(projectId)) {
      throw new Error(`invalid project id for attested-head path: ${projectId}`);
    }
    return join(dir, `${projectId}.attested.json`);
  };

  const evidencePathOf = (projectId: string): string => {
    if (!isProjectId(projectId)) {
      throw new Error(`invalid project id for attestation-evidence path: ${projectId}`);
    }
    return join(dir, `${projectId}.attestation-evidence.jsonl`);
  };

  /**
   * Appending evidence (the same discipline as the floor log: O_APPEND
   * + newline prefixing + waiting through fsync). It is kept separate
   * from the floor log's appendRecords because that one is specific to
   * the floor record type — the append's physical discipline
   * (full-length rewrite on short write + fsync) is carried by the
   * shared appendAll.
   */
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
            // Non-empty yet not a single record decodable = wholesale corruption
            return {
              floor: null,
              state: "corrupt",
              droppedRecords: outcome.droppedLines,
            } satisfies FloorLoadResult;
          }
          // An empty file may also be a remnant dropped between
          // open("a") and write (= never created)
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
      // A resolution is a ledger record that closes an intent (outside
      // the join's lattice). Do not fail it on an existing-conflict check
      // — recording a resolution only ever works toward more evidence
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
        // Only the body (`<id>.jsonl`). `<id>.attestation-evidence.jsonl`
        // etc. fall out for not matching the ID form (hex 64)
        const ids = new Set<string>();
        for (const name of names) {
          const match = /^(.+)\.jsonl$/.exec(name);
          if (match?.[1] !== undefined && isProjectId(match[1])) {
            ids.add(match[1]);
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
        // Missing and corrupt both become null (tracking the previous
        // attestation is best-effort — the consequence of losing it is a
        // resubmission of the same seq, which the server's idempotent
        // 204 absorbs)
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
        // tmp → rename substitution (never show a partial write to a
        // reader) — writeJsonFileAtomic does it. Tracking is a separate,
        // overwritable class (not a verified observation — floor.ts's doc)
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
