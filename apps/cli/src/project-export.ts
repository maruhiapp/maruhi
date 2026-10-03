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

import { createWriteStream } from "node:fs";
import { rm, stat, writeFile } from "node:fs/promises";
import { createGzip } from "node:zlib";

import type { ExportIdentities } from "@maruhi/api-schema";
import { ExportChangedError } from "@maruhi/api-schema";
import { Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { countNoun, displayText } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { toCliError } from "./failure.ts";
import type { VerifiedProject } from "./sync.ts";

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
function ensureAbsent(path: string): Effect.Effect<void, CliError> {
  return Effect.gen(function* () {
    const exists = yield* Effect.promise(() =>
      stat(path).then(
        () => true,
        () => false,
      ),
    );
    if (exists) {
      return yield* Effect.fail(
        cliError(`Refusing to overwrite ${displayText(path)} (choose another --out path)`),
      );
    }
  });
}

/** A gzip sink to the file (node streams — the CLI is not Worker code). */
class GzipFileSink {
  readonly #gzip = createGzip();
  readonly #file: ReturnType<typeof createWriteStream>;
  readonly #done: Promise<void>;
  #bytes = 0;

  constructor(path: string) {
    this.#file = createWriteStream(path, { flags: "wx" });
    this.#gzip.on("data", (chunk: Buffer) => {
      this.#bytes += chunk.length;
    });
    this.#done = new Promise<void>((resolve, reject) => {
      this.#file.on("finish", resolve);
      this.#file.on("error", reject);
      this.#gzip.on("error", reject);
    });
    // `finish` observes a failure through `#done`; after `abort` nobody
    // waits for it, and the teardown itself raises ERR_STREAM_DESTROYED on
    // a write still in flight — that rejection must not surface as an
    // unhandled one (the file is being removed; the caller already has the
    // error it is aborting for). Not a swallowed error: `finish` still fails
    this.#done.catch(() => undefined);
    this.#gzip.pipe(this.#file);
  }

  write(lines: readonly string[]): Promise<void> {
    if (lines.length === 0) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve, reject) => {
      this.#gzip.write(`${lines.join("\n")}\n`, (error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });
  }

  async finish(): Promise<number> {
    this.#gzip.end();
    await this.#done;
    return this.#bytes;
  }

  /** Tears both streams down and waits for the file descriptor to close (the file is removed afterwards). */
  abort(): Promise<void> {
    this.#gzip.destroy();
    return new Promise<void>((resolve) => {
      if (this.#file.closed || this.#file.destroyed) {
        resolve();
        return;
      }
      this.#file.once("close", () => resolve());
      this.#file.destroy();
    });
  }
}

/** A line as a JSON object, or null (the last line must be the trailer object). */
function parseObjectLine(line: string | undefined): Record<string, unknown> | null {
  if (line === undefined) {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(line);
    return typeof parsed === "object" && parsed !== null
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function parseTrailer(line: string | undefined): ExportTrailer | null {
  const trailer = parseObjectLine(line);
  if (trailer === null || trailer["kind"] !== "trailer") {
    return null;
  }
  const { rows, chainHeadSeq, chainHeadHashHex, auditMaxSeq } = trailer;
  if (
    typeof rows !== "object" ||
    rows === null ||
    typeof chainHeadSeq !== "number" ||
    typeof auditMaxSeq !== "number"
  ) {
    return null;
  }
  return {
    rows: rows as Readonly<Record<string, number>>,
    chainHeadSeq,
    chainHeadHashHex: typeof chainHeadHashHex === "string" ? chainHeadHashHex : null,
    auditMaxSeq,
  };
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

/** One full pass over the pages into a fresh file; "changed" = the project moved (the file is removed and the caller restarts). */
function exportOnce(input: ProjectExportInput): Effect.Effect<Attempt, CliError> {
  return Effect.gen(function* () {
    const sink = new GzipFileSink(input.outPath);
    // Every failure removes the partial file first (an incomplete export is
    // never kept, and the next run must not be refused as an overwrite)
    const discard = Effect.promise(async () => {
      await sink.abort();
      await rm(input.outPath, { force: true });
    });
    const fail = (error: CliError) => discard.pipe(Effect.andThen(Effect.fail(error)));
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
          Effect.catch((error) =>
            error instanceof ExportChangedError ? Effect.succeed(null) : fail(toCliError(error)),
          ),
        );
      if (response === null) {
        yield* discard;
        return { kind: "changed" } as const;
      }
      yield* Effect.tryPromise({
        try: () => sink.write(response.lines),
        catch: (error) =>
          cliError(
            `Writing ${displayText(input.outPath)} failed (${error instanceof Error ? error.name : "unknown"})`,
          ),
      }).pipe(Effect.catch(fail));
      lines += response.lines.length;
      last = response.lines[response.lines.length - 1] ?? last;
      // The mark the server read with this page's marks (ruling J revision,
      // round 5): on the last page, with the marks unchanged since the
      // first, "marked" means no write landed here after the export
      mirrorOf = response.head.mirrorOf ?? null;
      cursor = response.next;
      if (cursor === undefined) {
        const trailer = parseTrailer(last);
        if (trailer === null) {
          return yield* fail(
            cliError(
              "The server ended the export without a trailer line (an incomplete export is never kept)",
            ),
          );
        }
        const bytes = yield* Effect.tryPromise({
          try: () => sink.finish(),
          catch: (error) =>
            cliError(
              `Writing ${displayText(input.outPath)} failed (${error instanceof Error ? error.name : "unknown"})`,
            ),
        }).pipe(Effect.catch(fail));
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
    return yield* fail(
      cliError(
        `The server kept returning more pages past the ${MAX_PAGES}-page bound — stopping. This does not happen with an honest server; investigate the server if it persists`,
      ),
    );
  });
}

/** The identities companion of a completed attempt; null when its chain head is not the file's (the pair is mismatched). */
function companionFor(
  input: ProjectExportInput,
  attempt: Attempt,
  withoutData: (error: CliError) => Effect.Effect<never, CliError>,
): Effect.Effect<ExportIdentities | null, CliError> {
  if (attempt.kind === "changed") {
    return Effect.succeed(null);
  }
  return input.client.export.identities({ params: { projectId: input.projectId } }).pipe(
    Effect.catch((error) => withoutData(toCliError(error))),
    Effect.map((identities) =>
      identities.chainHeadHashHex === attempt.trailer.chainHeadHashHex ? identities : null,
    ),
  );
}

/** Pages the whole project into `outPath` (restarting when it changes), then writes the identities companion. */
export function projectExportOp(
  input: ProjectExportInput,
): Effect.Effect<ProjectExportResult, CliError> {
  return Effect.gen(function* () {
    const identitiesPath = identitiesPathOf(input.outPath);
    yield* ensureAbsent(input.outPath);
    yield* ensureAbsent(identitiesPath);
    // The companion is half of the export: without it the data file is
    // removed too (a migration needs both, and a stale pair is worse than none)
    const withoutData = (error: CliError) =>
      Effect.promise(() => rm(input.outPath, { force: true })).pipe(
        Effect.andThen(Effect.fail(error)),
      );
    // The companion is read at a chain head; a head other than the file's
    // trailer's is a mismatched pair (a member added or removed between
    // the two reads — the destination would refuse it as stale), so the
    // export starts over like any change (bounded)
    let attempt = yield* exportOnce(input);
    let identities = yield* companionFor(input, attempt, withoutData);
    for (
      let restarts = 0;
      (attempt.kind === "changed" || identities === null) && restarts < MAX_RESTARTS;
      restarts += 1
    ) {
      yield* Effect.promise(() => rm(input.outPath, { force: true }));
      attempt = yield* exportOnce(input);
      identities = yield* companionFor(input, attempt, withoutData);
    }
    if (attempt.kind === "changed" || identities === null) {
      yield* Effect.promise(() => rm(input.outPath, { force: true }));
      return yield* Effect.fail(toCliError(new ExportChangedError({ reason: "project-changed" })));
    }
    yield* Effect.tryPromise({
      try: () =>
        writeFile(identitiesPath, `${JSON.stringify(identities, null, 2)}\n`, { flag: "wx" }),
      catch: (error) =>
        cliError(
          `Writing ${displayText(identitiesPath)} failed (${error instanceof Error ? error.name : "unknown"})`,
        ),
    }).pipe(Effect.catch(withoutData));
    return {
      outPath: input.outPath,
      identitiesPath,
      bytes: attempt.bytes,
      lines: attempt.lines,
      trailer: attempt.trailer,
      identities,
      mark: attempt.mark,
    };
  });
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
