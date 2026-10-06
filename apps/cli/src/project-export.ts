// `maruhi project export` (AUTH_SPEC §11-6 — PF3, docs/notes/pf3-design.md):
// the owner takes the whole project out as a snapshot file another
// maruhi deployment's restore path imports unchanged.
//
// What is written: the evacuation format of docs/notes/hosted-ops.md
// §2-D (gzip NDJSON — header / table / row / trailer lines), fetched
// page by page over the authenticated API and gzipped here while it
// streams to disk, plus the identities companion
// (`<file>.identities.json`: the current members' provider identities,
// which the destination pre-binds to the chain's user ids).
//
// Diskless discipline: nothing in the file is a plaintext — it is the
// server's own content (ciphertext, the signed chain, wraps,
// statements, the audit log). Writing it is the explicit purpose of the
// command, like a backup; the command refuses to overwrite.
//
// TCB discipline: the pages are server-declared. The trailer's chain
// head is cross-checked against the verified view this command synced
// first; a mismatch is reported (an older head = the server answered
// from behind the verified view; a newer one = a write landed after the
// sync).
//
// Resource discipline: the output file is a scoped resource
// (acquireUseRelease) — every exit that is not a completed attempt
// removes it, so a failure, an interruption (Ctrl-C) or a defect never
// leaves a partial file behind (an incomplete export is never kept, and
// the next run must not be refused as an overwrite). The command's own
// run gains a matching onExit for the data/companion pair. Cleanup only
// removes what the run provably created: the `wx` creates are the
// ownership proof, so a file landing at a checked path after
// `ensureAbsent` — someone else's — is never deleted.

import { createWriteStream } from "node:fs";
import { createGzip } from "node:zlib";

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import type { ExportIdentities } from "@maruhi/api-schema";
import { ExportChangedError } from "@maruhi/api-schema";
import { Effect, Exit, FileSystem, Result, Schema } from "effect";

import type { MaruhiClient } from "./api.ts";
import type { VerifiedProject } from "./chain-sync.ts";
import { countNoun, displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";

/** How many times a changed project restarts the export before giving up. */
const MAX_RESTARTS = 3;
/** The bound on pages of one export (far above any project the storage guard admits). */
const MAX_PAGES = 100_000;

export interface ProjectExportInput {
  readonly client: MaruhiClient;
  readonly projectId: string;
  readonly verified: VerifiedProject;
  readonly outPath: string;
}

export interface ProjectExportResult {
  readonly outPath: string;
  readonly identitiesPath: string;
  readonly bytes: number;
  readonly lines: number;
  readonly trailer: ExportTrailer;
  readonly identities: ExportIdentities;
  /** Whether the project is frozen here (a mirror of the named origin) or still writable — read with the last page's marks. */
  readonly mark: ExportMark;
}

export type ExportMark =
  | { readonly kind: "frozen"; readonly sourceOrigin: string }
  | { readonly kind: "writable" };

/** The trailer line as the snapshot format writes it (the fields this command reports). */
interface ExportTrailer {
  readonly rows: Readonly<Record<string, number>>;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string | null;
  readonly auditMaxSeq: number;
}

function identitiesPathOf(outPath: string): string {
  return `${outPath}.identities.json`;
}

/** Refuses an existing file (an export never overwrites — a stale file next to a fresh one is how a migration goes wrong). */
const ensureAbsent = Effect.fn("project-export.ensureAbsent")(function* (
  path: string,
): Effect.fn.Return<void, CliError, FileSystem.FileSystem> {
  const fs = yield* FileSystem.FileSystem;
  // NotFound is the only error `exists` folds to absent — a check that
  // fails otherwise is a real error, never a silent "absent"
  const exists = yield* fs
    .exists(path)
    .pipe(
      Effect.mapError((error) =>
        cliError(
          `Checking ${displayText(path)} failed (${error.reason.cause instanceof Error ? error.reason.cause.name : "unknown"})`,
        ),
      ),
    );
  if (exists) {
    return yield* Effect.fail(
      cliError(`Refusing to overwrite ${displayText(path)} (choose another --out path)`),
    );
  }
});

/**
 * Removes a file, tolerating its absence. A removal failure is a defect
 * (there is no user-facing answer to "the cleanup itself failed").
 */
function removePath(path: string): Effect.Effect<void, never, FileSystem.FileSystem> {
  return FileSystem.FileSystem.pipe(
    Effect.andThen((fs) => fs.remove(path, { force: true })),
    Effect.orDie,
  );
}

/** A gzip sink to the file (node streams — the CLI is not Worker code). */
class GzipFileSink {
  readonly #gzip = createGzip();
  readonly #file: ReturnType<typeof createWriteStream>;
  readonly #path: string;
  #bytes = 0;
  /**
   * The first stream failure seen. A Node stream without an `error`
   * listener throws on failure — this listener lives for the sink's
   * whole lifetime (write/finish listen per wait only), so an error
   * landing between operations is recorded here and surfaces at the
   * next operation instead of crashing the process.
   */
  #failure: Error | null = null;
  /**
   * Whether this sink's `wx` open committed — the only proof the file is
   * this run's. An already-existing file makes the open fail EEXIST
   * instead (no `open` event), and that file must never be removed.
   */
  #ownsFile = false;

  constructor(path: string) {
    this.#path = path;
    this.#file = createWriteStream(path, { flags: "wx" });
    const record = (error: Error) => {
      this.#failure ??= error;
    };
    this.#file.on("error", record);
    this.#gzip.on("error", record);
    this.#file.once("open", () => {
      this.#ownsFile = true;
    });
    this.#gzip.on("data", (chunk: Buffer) => {
      this.#bytes += chunk.length;
    });
    this.#gzip.pipe(this.#file);
  }

  get ownsFile(): boolean {
    return this.#ownsFile;
  }

  #writeFailed(error: unknown): CliError {
    return cliError(
      `Writing ${displayText(this.#path)} failed (${error instanceof Error ? error.name : "unknown"})`,
    );
  }

  /** Appends the lines (each as one NDJSON line) — fails on a stream error already seen or landing during the write. */
  write(lines: readonly string[]): Effect.Effect<void, CliError> {
    // Everything the stream does happens inside the suspend — an effect
    // must not act while it is only being built
    return Effect.suspend(() => {
      if (lines.length === 0) {
        return Effect.void;
      }
      const prior = this.#failure;
      if (prior !== null) {
        return Effect.fail(this.#writeFailed(prior));
      }
      const file = this.#file;
      const gzip = this.#gzip;
      return Effect.callback<void, CliError>((resume) => {
        const detach = () => {
          file.off("error", onError);
          gzip.off("error", onError);
        };
        const onError = (error: Error) => {
          detach();
          resume(Effect.fail(this.#writeFailed(error)));
        };
        file.once("error", onError);
        gzip.once("error", onError);
        gzip.write(`${lines.join("\n")}\n`, (error) => {
          detach();
          resume(error ? Effect.fail(this.#writeFailed(error)) : Effect.void);
        });
        return Effect.sync(detach);
      });
    });
  }

  /** Ends the gzip and waits for the file's `finish`; resolves to the compressed byte count. */
  finish(): Effect.Effect<number, CliError> {
    return Effect.suspend(() => {
      const prior = this.#failure;
      const done =
        prior !== null
          ? Effect.fail(this.#writeFailed(prior))
          : Effect.callback<void, CliError>((resume) => {
              const file = this.#file;
              const gzip = this.#gzip;
              const detach = () => {
                file.off("finish", onFinish);
                file.off("error", onError);
                gzip.off("error", onError);
              };
              const onFinish = () => {
                detach();
                resume(Effect.void);
              };
              const onError = (error: Error) => {
                detach();
                resume(Effect.fail(this.#writeFailed(error)));
              };
              file.once("finish", onFinish);
              file.once("error", onError);
              gzip.once("error", onError);
              // end() must run after the listeners are attached — a
              // finish in the gap would never reach the callback
              if (file.writableFinished) {
                onFinish();
              } else {
                gzip.end();
              }
              return Effect.sync(detach);
            });
      return Effect.map(done, () => this.#bytes);
    });
  }

  /** Tears both streams down and waits for the file descriptor to close (the file is removed afterwards). */
  abort(): Effect.Effect<void> {
    return Effect.suspend(() =>
      Effect.callback<void>((resume) => {
        const file = this.#file;
        // Before the early return: an already-closed file (autoDestroy on
        // a refused open) must not leave the gzip's handle alive
        this.#gzip.destroy();
        if (file.closed || file.destroyed) {
          resume(Effect.void);
          return;
        }
        const onClose = () => resume(Effect.void);
        file.once("close", onClose);
        file.destroy();
        return Effect.sync(() => {
          file.off("close", onClose);
        });
      }),
    );
  }
}

/** The trailer line's wire shape (the snapshot format — what the client reads back out of `last`). */
const TrailerLineSchema = Schema.Struct({
  kind: Schema.Literal("trailer"),
  rows: Schema.Record(Schema.String, Schema.Number),
  chainHeadSeq: Schema.Number,
  chainHeadHashHex: Schema.Union([Schema.String, Schema.Null]),
  auditMaxSeq: Schema.Number,
});

function parseTrailer(line: string | undefined): ExportTrailer | null {
  if (line === undefined) {
    return null;
  }
  const decoded = Schema.decodeUnknownResult(Schema.fromJsonString(TrailerLineSchema))(line);
  return Result.isFailure(decoded) ? null : decoded.success;
}

type Attempt =
  | {
      readonly kind: "done";
      readonly bytes: number;
      readonly lines: number;
      readonly trailer: ExportTrailer;
      readonly mark: ExportMark;
    }
  | { readonly kind: "changed" };

/**
 * Which of the two outputs this run provably created — the only files a
 * cleanup may remove. `ensureAbsent` is a check, not ownership: a file
 * landing at a checked path afterwards belongs to someone else and must
 * never be deleted (the `wx` creates are the proof — they refuse EEXIST).
 */
interface OwnedOutputs {
  out: boolean;
  companion: boolean;
}

/**
 * One full pass over the pages into a fresh file. The file is a scoped
 * resource: any exit other than a completed attempt — a failure, a
 * project change, an interruption, a defect — removes it (when this
 * attempt created one at all).
 */
function exportOnce(
  input: ProjectExportInput,
  owned: OwnedOutputs,
): Effect.Effect<Attempt, CliError, FileSystem.FileSystem> {
  const outPath = input.outPath;
  return Effect.acquireUseRelease(
    // Ownership is per attempt — this one has not created anything yet
    Effect.sync(() => {
      owned.out = false;
      return new GzipFileSink(outPath);
    }),
    (sink) =>
      Effect.gen(function* () {
        let cursor: string | undefined;
        let lines = 0;
        let last: string | undefined;
        let mirrorOf: string | null = null;
        for (let page = 0; page < MAX_PAGES; page += 1) {
          const response = yield* input.client.export
            .page({
              params: { projectId: input.projectId },
              query: cursor === undefined ? {} : { cursor },
            })
            .pipe(
              Effect.catchTag("ExportChanged", () => Effect.succeed(null)),
              Effect.catch((error) => Effect.fail(toCliError(error))),
            );
          if (response === null) {
            // "changed" exits the use block: the release removes the
            // partial file, the caller restarts
            return { kind: "changed" } as const;
          }
          yield* sink.write(response.lines);
          lines += response.lines.length;
          last = response.lines[response.lines.length - 1] ?? last;
          // The mark the server read with this page's marks (ruling J
          // revision, round 5): on the last page, with the marks
          // unchanged since the first, "marked" means no write landed
          // here after the export
          mirrorOf = response.head.mirrorOf ?? null;
          cursor = response.next;
          if (cursor === undefined) {
            const trailer = parseTrailer(last);
            if (trailer === null) {
              return yield* Effect.fail(
                cliError(
                  "The server ended the export without a trailer line (an incomplete export is never kept)",
                ),
              );
            }
            const bytes = yield* sink.finish();
            return {
              kind: "done",
              bytes,
              lines,
              trailer,
              mark: (mirrorOf === null
                ? { kind: "writable" }
                : { kind: "frozen", sourceOrigin: mirrorOf }) satisfies ExportMark,
            } as const;
          }
        }
        return yield* Effect.fail(
          cliError(
            `The server kept returning more pages past the ${MAX_PAGES}-page bound — stopping. This does not happen with an honest server; investigate the server if it persists`,
          ),
        );
      }),
    (sink, exit) =>
      Effect.gen(function* () {
        owned.out ||= sink.ownsFile;
        if (Exit.isSuccess(exit) && exit.value.kind === "done") {
          return;
        }
        yield* sink.abort();
        // The open may have committed during the close wait — re-check
        // before deciding whether the file is this attempt's to remove
        owned.out ||= sink.ownsFile;
        if (owned.out) {
          yield* removePath(outPath);
          // The flag means "our file is on disk now" — clear it so a
          // later cleanup does not remove whatever lands next
          owned.out = false;
        }
      }),
  );
}

/** The identities companion of a completed attempt; null when its chain head is not the file's (the pair is mismatched). */
function companionFor(
  input: ProjectExportInput,
  attempt: Attempt,
): Effect.Effect<ExportIdentities | null, CliError> {
  if (attempt.kind === "changed") {
    return Effect.succeed(null);
  }
  return input.client.export.identities({ params: { projectId: input.projectId } }).pipe(
    Effect.catch((error) => Effect.fail(toCliError(error))),
    Effect.map((identities) =>
      identities.chainHeadHashHex === attempt.trailer.chainHeadHashHex ? identities : null,
    ),
  );
}

/**
 * The data file plus its companion. Either file the export wrote is
 * removed when the run exits without success (failure, interruption,
 * defect): a stale pair is worse than none — a migration needs both.
 */
function writePair(
  input: ProjectExportInput,
): Effect.Effect<ProjectExportResult, CliError, FileSystem.FileSystem> {
  const outPath = input.outPath;
  const identitiesPath = identitiesPathOf(outPath);
  const owned: OwnedOutputs = { out: false, companion: false };
  return Effect.gen(function* () {
    const fs = yield* FileSystem.FileSystem;
    let attempt = yield* exportOnce(input, owned);
    let identities = yield* companionFor(input, attempt);
    // The companion is read at a chain head; a head other than the file's
    // trailer's is a mismatched pair (a member added or removed between
    // the two reads — the destination would refuse it as stale), so the
    // export starts over like any change (bounded)
    for (
      let restarts = 0;
      (attempt.kind === "changed" || identities === null) && restarts < MAX_RESTARTS;
      restarts += 1
    ) {
      // A completed file whose companion was stale is still on disk;
      // a "changed" attempt already removed its own — and an attempt
      // whose wx open refused EEXIST created nothing (a foreign file at
      // the path is never this run's to delete)
      if (owned.out) {
        yield* removePath(outPath);
        owned.out = false;
      }
      attempt = yield* exportOnce(input, owned);
      identities = yield* companionFor(input, attempt);
    }
    if (attempt.kind === "changed" || identities === null) {
      return yield* Effect.fail(toCliError(new ExportChangedError({ reason: "project-changed" })));
    }
    yield* fs
      .writeFileString(identitiesPath, `${JSON.stringify(identities, null, 2)}\n`, { flag: "wx" })
      .pipe(
        // Success is the proof this run created the companion — a wx
        // open that refused EEXIST means the file belongs to someone
        // else and the cleanup must leave it alone. The write and its
        // ownership mark are one uninterruptible unit: an interrupt
        // delivered mid-write must not leave a file on disk that no
        // cleanup knows it may remove (the platform write honors the
        // abort signal but may already have committed the file)
        Effect.tap(
          Effect.sync(() => {
            owned.companion = true;
          }),
        ),
        Effect.mapError((error) =>
          cliError(
            `Writing ${displayText(identitiesPath)} failed (${
              error.reason.cause instanceof Error ? error.reason.cause.name : "unknown"
            })`,
          ),
        ),
        Effect.uninterruptible,
      );
    return {
      outPath,
      identitiesPath,
      bytes: attempt.bytes,
      lines: attempt.lines,
      trailer: attempt.trailer,
      identities,
      mark: attempt.mark,
    };
  }).pipe(
    // `ensureAbsent` stays outside this scope: a cleanup that ran on the
    // refusal exit would delete the user's pre-existing file — and even
    // inside it, only files this run provably created are removed
    Effect.onExit((exit) =>
      Exit.isSuccess(exit)
        ? Effect.void
        : Effect.gen(function* () {
            if (owned.out) {
              yield* removePath(outPath);
            }
            if (owned.companion) {
              yield* removePath(identitiesPath);
            }
          }),
    ),
  );
}

/** Pages the whole project into `outPath` (restarting when it changes), then writes the identities companion. */
export function projectExportOp(
  input: ProjectExportInput,
): Effect.Effect<ProjectExportResult, CliError> {
  const outPath = input.outPath;
  const identitiesPath = identitiesPathOf(outPath);
  return Effect.gen(function* () {
    yield* ensureAbsent(outPath);
    yield* ensureAbsent(identitiesPath);
    return yield* writePair(input);
    // BunFileSystem is provided inside the module (config.ts discipline):
    // the command environment's FileSystem is deliberately a dying stub
    // (cli-runner.ts), so the env must not supply it
  }).pipe(Effect.provide(BunFileSystem.layer));
}

/** What the export's mark means for the migration (the next steps follow it). */
function describeMark(mark: ExportMark): string {
  return mark.kind === "frozen"
    ? `This project is frozen here (a mirror of ${mark.sourceOrigin}): nothing can land on this server after the export`
    : "Warning: this project is still writable here — a write after this export does not reach the destination. For a migration, freeze it first with `maruhi mirror mark --source <destination url>` and re-export if anything changed in between";
}

/** The report (counts and heads only — no row content). */
export function describeExport(result: ProjectExportResult, verified: VerifiedProject): string[] {
  const { trailer } = result;
  const rows = Object.entries(trailer.rows)
    .filter(([, count]) => count > 0)
    .toSorted(([a], [b]) => a.localeCompare(b))
    .map(([table, count]) => `${table}=${count}`)
    .join(", ");
  const headNote =
    trailer.chainHeadHashHex === verified.state.headHashHex
      ? "matches the verified view"
      : trailer.chainHeadSeq > verified.state.headSeq
        ? `newer than the verified view (seq ${verified.state.headSeq}) — a write landed after the sync; re-run \`maruhi project verify\` before relying on it`
        : trailer.chainHeadSeq === verified.state.headSeq
          ? `a different chain at the same height as the verified view (head ${verified.state.headHashHex}) — evidence of a fork (CRYPTO_SPEC §6.3); do not import this file and run \`maruhi project verify\``
          : `behind the verified view (seq ${verified.state.headSeq}, head ${verified.state.headHashHex}) — the server answered from an older state; do not import this file`;
  const unlinked =
    result.identities.unlinked.length === 0
      ? []
      : [
          `Warning: ${countNoun(result.identities.unlinked.length, "member")} has no linked identity on this server (${result.identities.unlinked.map(displayText).join(", ")}); the destination cannot pre-bind them and they will not be able to log in as their chain identity`,
        ];
  return [
    `Exported project ${displayText(result.outPath)} (${result.bytes} bytes gzip, ${countNoun(result.lines, "line")}): chain head seq=${trailer.chainHeadSeq} ${headNote}; audit seq=${trailer.auditMaxSeq}; rows: ${rows}`,
    `Identities companion: ${displayText(result.identitiesPath)} (${countNoun(result.identities.identities.length, "member identity")}, exported by ${displayText(result.identities.exportedBy)})`,
    ...unlinked,
    describeMark(result.mark),
    "Next: place both files in the destination deployment's ops bucket and submit a restore job with `identitiesKey` (SELF_HOSTING.md — Migrating a project; a `drill` job rehearses it first). After the import: every member logs in to the destination (`maruhi login --server <url>`) and points the CLI at it (`maruhi config set server <url>`), the owner revokes this server's key and grants the destination's (`maruhi server revoke` / `maruhi server grant`), then rotates the environments the old key could open (`maruhi env rotate`)",
  ];
}
