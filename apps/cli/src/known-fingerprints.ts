// The verified-fingerprint ledger (KF — ROADMAP /
// integration-options.md §3 supplement 17, turn A).
//
// Because keys **belong to devices and permissions to people**
// (CRYPTO_SPEC §3 — 2026-09-19 DK), the fingerprint of a counterparty's
// device key confirmed out of band once via the 12-word ceremony stays
// valid until that key is revoked. Since a counterparty holds a **set**
// of device keys, one person's row in the ledger is a set of
// fingerprints (design record dk-design.md §9 K4 — (origin, user_id) →
// { FP → confirmed-at }). When the CLI keeps "the (origin, user_id) →
// fingerprint set I confirmed" as non-sensitive config (the same idea as
// SSH's known_hosts), the next ceremony involving the same person can
// skip **re-running** the 12-word out-of-band read-out. However a ledger
// match only means "this key was verified before" and **never substitutes
// for the human's consent to this acceptance / grant**: even on a hit,
// the per-acceptance explicit confirmation (typing yes) stays, and an
// agent environment never uses the ledger as an auto-pass (the flag
// stays required). Further, the ledger is usable only when stdin /
// stdout are interactive terminals (the same allow-list as ADR-0016
// decision 7's first boundary — unlike the 12-word ceremony, a yes
// confirmation passes a blind pipe, so under pipes / CI / undetected
// agents the ledger is disabled and the full ceremony returns). Since an
// invite link is bearer and carries no invitee identity, a ledger match
// alone never automates up to granting (kept within CRYPTO_SPEC §6.5's
// mutual-confirmation UX).
//
// - The content is public information only (key fingerprints) —
//   compatible with the diskless invariant
// - **A mismatch is never auto-passed** (warning + fall back to the
//   normal ceremony). It is also never an automatic failure, since a
//   legitimate key regeneration (`maruhi key generate`) is possible
// - Unlike per-project pins (invites/<projectId>.json), the goal is
//   per-user, cross-project, so a single file (<config
//   dir>/known-fingerprints.json)
// - fail-open: a missing file = no records, corrupt = no records + a
//   distinguishable warning (emitted by the caller). A failed record
//   write also never blocks the ceremony's establishment (SHOULD level).
//   An attacker who can delete local state is outside the ledger's
//   coverage (deletion only returns you to the ceremony — fail-closed,
//   safer than pins)

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { Context, Effect, Stdio } from "effect";

import { describeNonTerminal } from "./agent-gate.ts";
import { displayText, formatUtcMinutes } from "./display.ts";
import { cliError, type CliError } from "./errors.ts";
import { floorRecordGet } from "./floor.ts";
import { CliIo } from "./io.ts";
import { isRecord } from "./json-record.ts";
import { logNote, logWarning } from "./notice.ts";
import { BOOK_KEY, decodeOriginBook } from "./origin-book.ts";

/** One person's records verified out of band. */
export interface KnownFingerprint {
  /** The user key FP (16-byte hex, 32 characters — CRYPTO_SPEC §3). */
  readonly fingerprintHex: string;
  /** When the human performed the out-of-band confirmation (not refreshed on a hit — a record of the verification's fact). */
  readonly verifiedAtMs: number;
}

/** One person: the set of confirmed fingerprints (FP → confirmed-at). */
interface KnownUser {
  readonly fingerprints: Readonly<Record<string, { readonly verifiedAtMs: number }>>;
}

/**
 * The whole file (known-fingerprints.json). Keys are origin → user_id →
 * fingerprint set (v2 — DK).
 */
interface FingerprintBookFile {
  readonly v: 2;
  readonly known: Readonly<Record<string, Readonly<Record<string, KnownUser>>>>;
}

/** The lookup result. corrupt is distinguished from miss (the caller emits the warning). */
export type FingerprintLookup =
  | { readonly state: "hit"; readonly entries: readonly KnownFingerprint[] }
  | { readonly state: "miss" }
  | { readonly state: "corrupt" };

/** Lookup / record boundary for the verified-fingerprint book. */
export interface FingerprintBookShape {
  /** The file path for display (the path that lets deleting an entry force the ceremony to re-run). */
  readonly filePath: string;
  readonly lookup: (origin: string, userId: string) => Effect.Effect<FingerprintLookup, CliError>;
  /** A read-merge-write append (adds a fingerprint to the same person's set; the same fingerprint refreshes its confirmation time). */
  readonly record: (
    origin: string,
    userId: string,
    fingerprintHex: string,
  ) => Effect.Effect<void, CliError>;
}

export class FingerprintBook extends Context.Service<FingerprintBook, FingerprintBookShape>()(
  "cli/FingerprintBook",
) {}

/** Where the ledger lives (same family as the config: <parent of config.json>/known-fingerprints.json). */
export function fingerprintBookPathOf(configPath: string): string {
  return join(dirname(configPath), "known-fingerprints.json");
}

/** The result of the pre-ceremony consultation (the caller's branching material). */
export interface FingerprintBookConsult {
  /**
   * The matching ledger entry (null = no hit / mismatch / corrupt =
   * needs the usual ceremony or a flag). A hit goes to
   * confirmKnownFingerprint (the per-acceptance explicit confirmation).
   * The discipline that the flag (an explicit designation) beats the
   * ledger and the agent-environment refusal are kept by the caller (the
   * ledger bypasses neither).
   */
  readonly hit: KnownFingerprint | null;
  /** The file path for display (the path that lets deleting an entry force the ceremony to re-run). */
  readonly filePath: string;
  /**
   * The warning for a **mismatch** between the ledger's records and the
   * presented fingerprint (a no-op on match or no records). Called
   * **after** the flag path is decided — when the flag matches the
   * presented fingerprint but only the ledger is stale (e.g. running via
   * the flag right after a legitimate key update), this prevents "the
   * out-of-band check is required again" from contradicting the flag's
   * success.
   */
  readonly warnIfChanged: Effect.Effect<void, never, CliIo>;
  /**
   * The append called **after** the ceremony / flag check succeeds. A
   * write failure degrades to a warning (fail-open — the ledger is
   * SHOULD-level and never blocks the ceremony's establishment).
   */
  readonly record: Effect.Effect<void, never, CliIo>;
}

/**
 * The pre-ceremony ledger consultation (shared by member add's
 * acceptance-key check and invite accept's inviter check): a match =
 * the 12-word out-of-band read-out may be skipped (the per-acceptance
 * explicit confirmation is still required by confirmKnownFingerprint);
 * a mismatch = warn and fall back to the ceremony (**never an automatic
 * failure** — a legitimate key update via `maruhi key generate` is
 * possible); corrupt = warn and treat as no records.
 */
export function consultFingerprintBook(input: {
  readonly origin: string;
  readonly userId: string;
  readonly fingerprintHex: string;
}): Effect.Effect<FingerprintBookConsult, CliError, FingerprintBook | CliIo> {
  return Effect.gen(function* () {
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
  });
}

/**
 * Judges whether a ledger hit may actually be used (no flag + non-agent
 * + stdin / stdout interactive terminals) and returns only a usable hit.
 * When a hit is unusable on terminal grounds alone, a note explains so
 * (showing the reason the full ceremony returns).
 *
 * Why terminal conditions are imposed (the same allow-list as ADR-0016
 * decision 7's first boundary): the 12-word ceremony requires re-typing
 * the last word on each run so a blind pipe cannot pass it, but a yes
 * confirmation is not so. On pipes / CI / undetected agents the ledger
 * must not loosen the non-interactive establishment condition beyond
 * flag-only (fail-closed — a non-terminal returns to behaving as if the
 * ledger did not exist).
 */
export function usableBookHit(input: {
  readonly book: FingerprintBookConsult;
  readonly flagProvided: boolean;
  readonly isAgent: boolean;
}): Effect.Effect<KnownFingerprint | null, never, CliIo | Stdio.Stdio> {
  return Effect.gen(function* () {
    if (input.book.hit === null || input.flagProvided || input.isAgent) {
      return null;
    }
    const stdio = yield* Stdio.Stdio;
    const stdinIsTerminal = yield* stdio.stdinIsTerminal;
    const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
    if (!stdinIsTerminal || !stdoutIsTerminal) {
      // Name the side that failed (the DP5 supplement G discipline — describeNonTerminal)
      yield* logNote(
        `the verified-fingerprint book was not used: ${describeNonTerminal({ stdinIsTerminal, stdoutIsTerminal })} — the full 12-word read-out is required here`,
      );
      return null;
    }
    return input.book.hit;
  });
}

/**
 * The per-acceptance explicit confirmation on a ledger hit: re-running
 * the 12-word out-of-band read-out is waived, but **the consent to this
 * operation (granting / accepting) itself is never omitted** — the
 * ledger is a record that "this key was verified out of band before" and
 * does not substitute for the intent of this operation. `prompt` is the
 * wording naming the target and operation (given by the caller). Any
 * answer but yes aborts and shows the way back to the full ceremony
 * (deleting the entry).
 */
export function confirmKnownFingerprint(input: {
  readonly entry: KnownFingerprint;
  readonly filePath: string;
  /** The prompt body up to just before `: ` (e.g. "Type yes to add … as …"). */
  readonly prompt: string;
  /** The leading sentence on abort (e.g. "add_member was cancelled."). */
  readonly cancelText: string;
}): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
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
  });
}

const HEX_32 = /^[0-9a-f]{32}$/;

function validTimestamp(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

/** One person's record (`{ fingerprints: { FP: { verifiedAtMs } } }`). */
function decodeUser(value: unknown): KnownUser | null {
  if (!isRecord(value) || !isRecord(value["fingerprints"])) {
    return null;
  }
  const fingerprints: Record<string, { readonly verifiedAtMs: number }> = {};
  for (const [fingerprintHex, raw] of Object.entries(value["fingerprints"])) {
    if (!HEX_32.test(fingerprintHex) || !isRecord(raw) || !validTimestamp(raw["verifiedAtMs"])) {
      return null;
    }
    fingerprints[fingerprintHex] = { verifiedAtMs: raw["verifiedAtMs"] };
  }
  return { fingerprints };
}

/** Decoding one origin's worth (user_id → set) (one invalid entry rejects the whole). */
function decodeUsers(value: unknown): Record<string, KnownUser> | null {
  if (!isRecord(value)) {
    return null;
  }
  const users: Record<string, KnownUser> = {};
  for (const [userId, raw] of Object.entries(value)) {
    const entry = decodeUser(raw);
    if (entry === null || !BOOK_KEY.test(userId)) {
      return null;
    }
    users[userId] = entry;
  }
  return users;
}

/** Strict decode (v2). One invalid entry treats the whole as corrupt (no partial reads — same as pins). */
function decodeBook(json: string): FingerprintBookFile | null {
  const known = decodeOriginBook(json, 2, decodeUsers);
  return known === null ? null : { v: 2, known };
}

/** The set → the lookup result's entry list (ascending FP). */
function entriesOf(user: KnownUser): readonly KnownFingerprint[] {
  return Object.entries(user.fingerprints)
    .map(([fingerprintHex, { verifiedAtMs }]) => ({ fingerprintHex, verifiedAtMs }))
    .toSorted((a, b) => (a.fingerprintHex < b.fingerprintHex ? -1 : 1));
}

/** File-backed fingerprint book at `path` (used by both production and tests). */
export function makeFileFingerprintBook(path: string): FingerprintBookShape {
  const loadRaw = async (): Promise<
    | { readonly book: FingerprintBookFile; readonly state: "loaded" }
    | { readonly state: "missing" }
    | { readonly state: "corrupt" }
  > => {
    let json: string;
    try {
      json = await readFile(path, "utf8");
    } catch (error) {
      // **Only** uncreated (ENOENT) folds into "none". Folding EACCES /
      // EISDIR / EIO etc. into "none" would let record overwrite with an
      // empty book and silently lose verified FPs, and let lookup return
      // miss, silencing the change warning (the same discipline as
      // pins.ts / config.ts)
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return { state: "missing" };
      }
      throw error;
    }
    const book = decodeBook(json);
    return book === null ? { state: "corrupt" } : { book, state: "loaded" };
  };

  const write = async (book: FingerprintBookFile): Promise<void> => {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    const temp = `${path}.${process.pid}.tmp`;
    await writeFile(temp, `${JSON.stringify(book, null, 2)}\n`, { mode: 0o600 });
    await rename(temp, path);
  };

  return {
    filePath: path,
    lookup: (origin, userId) =>
      Effect.tryPromise({
        try: async (): Promise<FingerprintLookup> => {
          const loaded = await loadRaw();
          if (loaded.state === "missing") {
            return { state: "miss" };
          }
          if (loaded.state === "corrupt") {
            return { state: "corrupt" };
          }
          // own-property lookup (floor.ts's discipline — never pick up a value via the prototype)
          const users = floorRecordGet(loaded.book.known, origin);
          const user = users === undefined ? undefined : floorRecordGet(users, userId);
          const entries = user === undefined ? [] : entriesOf(user);
          return entries.length === 0 ? { state: "miss" } : { state: "hit", entries };
        },
        catch: () => cliError(`Cannot read the verified-fingerprint book: ${path}`),
      }),
    record: (origin, userId, fingerprintHex) =>
      Effect.tryPromise({
        try: async () => {
          // Writing an off-form key would make the next load wholly
          // corrupt (strict decode), so refuse beforehand (the caller
          // degrades to a warning — fail-open)
          if (!BOOK_KEY.test(origin) || !BOOK_KEY.test(userId) || !HEX_32.test(fingerprintHex)) {
            throw new Error("key form");
          }
          const loaded = await loadRaw();
          if (loaded.state === "corrupt") {
            // Refuse to overwrite a corrupt file (the same discipline as
            // pins' merge — never silently erase the traces of an
            // unintended change)
            throw new Error("corrupt");
          }
          const base: FingerprintBookFile =
            loaded.state === "missing" ? { v: 2, known: {} } : loaded.book;
          const users = floorRecordGet(base.known, origin) ?? {};
          const user = floorRecordGet(users, userId) ?? { fingerprints: {} };
          await write({
            v: 2,
            known: {
              ...base.known,
              [origin]: {
                ...users,
                [userId]: {
                  fingerprints: {
                    ...user.fingerprints,
                    [fingerprintHex]: { verifiedAtMs: Date.now() },
                  },
                },
              },
            },
          });
        },
        catch: () =>
          cliError(
            `Cannot write the verified-fingerprint book (corrupt or an I/O failure): ${path} — inspect it, and if the modification was unintended, delete it and re-run`,
          ),
      }),
  };
}
