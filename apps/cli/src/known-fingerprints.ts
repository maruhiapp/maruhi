import { dirname, join } from "node:path";

import * as BunFileSystem from "@effect/platform-bun/BunFileSystem";
import { type UserId } from "@maruhi/core";
import { Clock, Context, Effect, Schema, Stdio } from "effect";

import { describeNonTerminal } from "./agent-gate.ts";
import { displayText, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { floorRecordGet } from "./floor.ts";
import { CliIo } from "./io.ts";
import { PositiveInt, readJsonFile, recordKeysMatch, writeJsonFileAtomic } from "./json-record.ts";
import { logNote, logWarning } from "./notice.ts";
import { BOOK_KEY, originBookSchema } from "./origin-book.ts";

export interface KnownFingerprint {
  readonly fingerprintHex: string;
  readonly verifiedAtMs: number;
}

interface KnownUser {
  readonly fingerprints: Readonly<Record<string, { readonly verifiedAtMs: number }>>;
}

interface FingerprintBookFile {
  readonly v: 2;
  readonly known: Readonly<Record<string, Readonly<Record<string, KnownUser>>>>;
}

export type FingerprintLookup =
  | { readonly state: "hit"; readonly entries: readonly KnownFingerprint[] }
  | { readonly state: "miss" }
  | { readonly state: "corrupt" };

export interface FingerprintBookShape {
  readonly filePath: string;
  readonly lookup: (origin: string, userId: UserId) => Effect.Effect<FingerprintLookup, CliError>;
  readonly record: (
    origin: string,
    userId: UserId,
    fingerprintHex: string,
  ) => Effect.Effect<void, CliError>;
}

export class FingerprintBook extends Context.Service<FingerprintBook, FingerprintBookShape>()(
  "cli/FingerprintBook",
) {}

export function fingerprintBookPathOf(configPath: string): string {
  return join(dirname(configPath), "known-fingerprints.json");
}

interface FingerprintBookConsult {
  readonly hit: KnownFingerprint | null;
  readonly filePath: string;
  readonly warnIfChanged: Effect.Effect<void, never, CliIo>;
  readonly record: Effect.Effect<void, never, CliIo>;
}

export const consultFingerprintBook = Effect.fn("known-fingerprints.consultFingerprintBook")(
  function* (input: {
    readonly origin: string;
    readonly userId: UserId;
    readonly fingerprintHex: string;
  }): Effect.fn.Return<FingerprintBookConsult, CliError, FingerprintBook | CliIo> {
    const book = yield* FingerprintBook;
    const looked = yield* book.lookup(input.origin, input.userId);
    if (looked.state === "corrupt") {
      yield* logWarning(
        `the verified-fingerprint book is corrupt and was ignored: ${book.filePath} — inspect it, and delete it if the change was not intentional`,
      );
    }
    const matched =
      looked.state === "hit"
        ? looked.entries.find((entry) => entry.fingerprintHex === input.fingerprintHex)
        : undefined;
    const warnIfChanged =
      looked.state === "hit" && matched === undefined
        ? logWarning(
            `this fingerprint is not among the ${looked.entries.length === 1 ? "one" : String(looked.entries.length)} verified for ${displayText(input.userId)} on this machine (${looked.entries.map((entry) => `${entry.fingerprintHex} on ${formatUtcMinutes(entry.verifiedAtMs)}`).join(", ")}). The person may have added a device (\`maruhi device approve\`) or rebuilt their key, or this is not their key — the out-of-band check is required again`,
          )
        : Effect.void;
    const record = book.record(input.origin, input.userId, input.fingerprintHex).pipe(
      Effect.flatMap(() =>
        logNote(
          `recorded the verified fingerprint for ${displayText(input.userId)} — future ceremonies with this person's key skip the 12-word read-out (a new device of theirs needs its own read-out; delete the entry in ${book.filePath} to force the full ceremony again)`,
        ),
      ),
      Effect.catch((error) =>
        logWarning(
          `could not record the verified fingerprint (${error.message}). The next ceremony with this person will require the full read-out again`,
        ),
      ),
    );
    const hit = matched ?? null;
    return { hit, filePath: book.filePath, warnIfChanged, record };
  },
);

export const usableBookHit = Effect.fn("known-fingerprints.usableBookHit")(function* (input: {
  readonly book: FingerprintBookConsult;
  readonly flagProvided: boolean;
  readonly isAgent: boolean;
}): Effect.fn.Return<KnownFingerprint | null, never, CliIo | Stdio.Stdio> {
  if (input.book.hit === null || input.flagProvided || input.isAgent) {
    return null;
  }
  const stdio = yield* Stdio.Stdio;
  const stdinIsTerminal = yield* stdio.stdinIsTerminal;
  const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
  if (!stdinIsTerminal || !stdoutIsTerminal) {
    yield* logNote(
      `the verified-fingerprint book was not used: ${describeNonTerminal({ stdinIsTerminal, stdoutIsTerminal })} — the full 12-word read-out is required here`,
    );
    return null;
  }
  return input.book.hit;
});

export const confirmKnownFingerprint = Effect.fn("known-fingerprints.confirmKnownFingerprint")(
  function* (input: {
    readonly entry: KnownFingerprint;
    readonly filePath: string;
    readonly prompt: string;
    readonly cancelText: string;
  }): Effect.fn.Return<void, CliError, CliIo> {
    const io = yield* CliIo;
    yield* io.log(
      `This fingerprint was verified out of band on this machine on ${formatUtcMinutes(input.entry.verifiedAtMs)} (the verified-fingerprint book), so the 12-word read-out is not required again`,
    );
    const answer = yield* io.promptLine({ prompt: `${input.prompt}: ` });
    if (answer.trim().toLowerCase() !== "yes") {
      return yield* Effect.fail(
        cliError(
          `${input.cancelText} To run the full 12-word ceremony instead, delete this person's entry in ${input.filePath} and re-run`,
        ),
      );
    }
  },
);

const HEX_32 = /^[0-9a-f]{32}$/;

const KnownUserSchema = Schema.Struct({
  fingerprints: Schema.Record(Schema.String, Schema.Struct({ verifiedAtMs: PositiveInt })).check(
    recordKeysMatch(HEX_32),
  ),
});

const BookFileSchema = originBookSchema(2, KnownUserSchema);

function entriesOf(user: KnownUser): readonly KnownFingerprint[] {
  return Object.entries(user.fingerprints)
    .map(([fingerprintHex, { verifiedAtMs }]) => ({ fingerprintHex, verifiedAtMs }))
    .toSorted((a, b) => (a.fingerprintHex < b.fingerprintHex ? -1 : 1));
}

export function makeFileFingerprintBook(path: string): FingerprintBookShape {
  const writeError = () =>
    cliError(
      `Cannot write the verified-fingerprint book (corrupt or an I/O failure): ${path} — inspect it, and if the modification was unintended, delete it and re-run`,
    );

  const load = () =>
    readJsonFile(path, BookFileSchema).pipe(
      Effect.mapError(() => cliError(`Cannot read the verified-fingerprint book: ${path}`)),
      Effect.provide(BunFileSystem.layer),
    );

  return {
    filePath: path,
    lookup: Effect.fn("known-fingerprints.lookup")(function* (origin, userId): Effect.fn.Return<
      FingerprintLookup,
      CliError
    > {
      const loaded = yield* load();
      if (loaded.state === "missing") {
        return { state: "miss" };
      }
      if (loaded.state === "corrupt") {
        return { state: "corrupt" };
      }
      const users = floorRecordGet(loaded.file.known, origin);
      const user = users === undefined ? undefined : floorRecordGet(users, userId);
      const entries = user === undefined ? [] : entriesOf(user);
      return entries.length === 0 ? { state: "miss" } : { state: "hit", entries };
    }),
    record: Effect.fn("known-fingerprints.record")(
      function* (origin, userId, fingerprintHex) {
        if (!BOOK_KEY.test(origin) || !BOOK_KEY.test(userId) || !HEX_32.test(fingerprintHex)) {
          return yield* Effect.fail(writeError());
        }
        const loaded = yield* load();
        if (loaded.state === "corrupt") {
          return yield* Effect.fail(writeError());
        }
        const base: FingerprintBookFile =
          loaded.state === "missing" ? { v: 2, known: {} } : loaded.file;
        const users = floorRecordGet(base.known, origin) ?? {};
        const user = floorRecordGet(users, userId) ?? { fingerprints: {} };
        const verifiedAtMs = yield* Clock.currentTimeMillis;
        yield* writeJsonFileAtomic(path, BookFileSchema, {
          v: 2,
          known: {
            ...base.known,
            [origin]: {
              ...users,
              [userId]: {
                fingerprints: {
                  ...user.fingerprints,
                  [fingerprintHex]: { verifiedAtMs },
                },
              },
            },
          },
        });
      },
      Effect.mapError(writeError),
      Effect.provide(BunFileSystem.layer),
    ),
  };
}
