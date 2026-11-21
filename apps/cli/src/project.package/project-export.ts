import { createWriteStream } from "node:fs";
import { createGzip } from "node:zlib";

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import type { ExportIdentities } from "@maruhi/api-schema";
import { ExportChangedError } from "@maruhi/api-schema";
import { type ProjectId } from "@maruhi/core";
import { Effect, Exit, FileSystem, Result, Schema } from "effect";

import type { MaruhiClient } from "../api.ts";
import type { VerifiedProject } from "../chain-sync.ts";
import { countNoun, displayText } from "../display.ts";
import { cliError, type CliError } from "../errors.ts";
import { toCliError } from "../failure.ts";

const MAX_RESTARTS = 3;
const MAX_PAGES = 100_000;

export interface ProjectExportInput {
  readonly client: MaruhiClient;
  readonly projectId: ProjectId;
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
  readonly mark: ExportMark;
}

export type ExportMark =
  | { readonly kind: "frozen"; readonly sourceOrigin: string }
  | { readonly kind: "writable" };

interface ExportTrailer {
  readonly rows: Readonly<Record<string, number>>;
  readonly chainHeadSeq: number;
  readonly chainHeadHashHex: string | null;
  readonly auditMaxSeq: number;
}

function identitiesPathOf(outPath: string): string {
  return `${outPath}.identities.json`;
}

const ensureAbsent = Effect.fn("project-export.ensureAbsent")(function* (
  path: string,
): Effect.fn.Return<void, CliError, FileSystem.FileSystem> {
  const fs = yield* FileSystem.FileSystem;
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

function removePath(path: string): Effect.Effect<void, never, FileSystem.FileSystem> {
  return FileSystem.FileSystem.pipe(
    Effect.andThen((fs) => fs.remove(path, { force: true })),
    Effect.orDie,
  );
}

class GzipFileSink {
  readonly #gzip = createGzip();
  readonly #file: ReturnType<typeof createWriteStream>;
  readonly #path: string;
  #bytes = 0;
  #failure: Error | null = null;
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

  write(lines: readonly string[]): Effect.Effect<void, CliError> {
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

  abort(): Effect.Effect<void> {
    return Effect.suspend(() =>
      Effect.callback<void>((resume) => {
        const file = this.#file;
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

interface OwnedOutputs {
  out: boolean;
  companion: boolean;
}

function exportOnce(
  input: ProjectExportInput,
  owned: OwnedOutputs,
): Effect.Effect<Attempt, CliError, FileSystem.FileSystem> {
  const outPath = input.outPath;
  return Effect.acquireUseRelease(
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
            return { kind: "changed" } as const;
          }
          yield* sink.write(response.lines);
          lines += response.lines.length;
          last = response.lines[response.lines.length - 1] ?? last;
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
        owned.out ||= sink.ownsFile;
        if (owned.out) {
          yield* removePath(outPath);
          owned.out = false;
        }
      }),
  );
}

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
    for (
      let restarts = 0;
      (attempt.kind === "changed" || identities === null) && restarts < MAX_RESTARTS;
      restarts += 1
    ) {
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

export function projectExportOp(
  input: ProjectExportInput,
): Effect.Effect<ProjectExportResult, CliError> {
  const outPath = input.outPath;
  const identitiesPath = identitiesPathOf(outPath);
  return Effect.gen(function* () {
    yield* ensureAbsent(outPath);
    yield* ensureAbsent(identitiesPath);
    return yield* writePair(input);
  }).pipe(Effect.provide(BunFileSystem.layer));
}

function describeMark(mark: ExportMark): string {
  return mark.kind === "frozen"
    ? `This project is frozen here (a mirror of ${mark.sourceOrigin}): nothing can land on this server after the export`
    : "Warning: this project is still writable here — a write after this export does not reach the destination. For a migration, freeze it first with `maruhi mirror mark --source <destination url>` and re-export if anything changed in between";
}

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
