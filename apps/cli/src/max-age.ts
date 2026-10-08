// Expiring values (PF6 R9 — CRYPTO_SPEC §4.2 layout v3 `max_age_days`) and
// the PF7a nudges built on them (docs/notes/pf7-pf8-design.md §2):
//
//   - `maruhi rotation list` prints the values past, or close to, the max
//     age their schema declares, and `--fail-on-due` turns that into a
//     non-zero exit a CI cron can act on (S-B of pf6-design.md §10-1)
//   - `maruhi run` / `maruhi pull` print one note when a value they just
//     pulled is past its max age (S-E — the nudge at the point of use)
//
// The max age comes from the verified statement (signed); the push time is
// the history's server-declared `pushedAtMs` (advisory — the same material
// `maruhi var history` shows). Nothing here reads a value: the input is a
// name, a declared interval, and a timestamp. The history calls are bounded
// by the number of declared intervals and run concurrently, so a `run`
// pays one round-trip time whatever the count (the pull wire carries no
// push time — AUTH_SPEC §12-7; pf6-design.md ruling R9-C kept it that way).

import { type EnvironmentId, type ProjectId, type VariableId } from "@maruhi/core";
import { Clock, Duration, Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { countNoun, displayText, formatUtcDate } from "./display.ts";
import type { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";
import type { DecryptedVariable } from "./pull.ts";

export const DAY_MS = 24 * 60 * 60 * 1000;
/** How far ahead `rotation list`'s "due soon" looks (also the `--due-within` default). */
export const DUE_SOON_DAYS = 14;

/** A variable whose verified statement declares a max age (the only kind this module looks at). */
export interface MaxAgeCandidate {
  readonly variableId: VariableId;
  readonly name: string;
  readonly maxAgeDays: number;
}

/** One value past, or approaching, its declared max age. */
export interface DueRow {
  readonly environmentId: EnvironmentId;
  readonly variableId: VariableId;
  readonly name: string;
  readonly maxAgeDays: number;
  readonly pushedAtMs: number;
  readonly dueAtMs: number;
}

/** The rows due inside the window plus the variables whose age could not be judged (history read failed). */
export interface DueRows {
  readonly rows: readonly DueRow[];
  /** The names of the candidates whose history could not be read (noted on stderr already). */
  readonly unreadable: readonly string[];
  /** The environments whose verified metadata could not be read at all (their candidates are unknown — noted on stderr already). */
  readonly unreadableEnvironments: readonly string[];
}

/** The bound on one history read (an advisory lookup never holds the command — B-7). */
const HISTORY_TIMEOUT = Duration.seconds(10);

/**
 * The due rows of one environment: each candidate's latest push time is
 * read from the history (concurrently — one round-trip time in all), the
 * due date is push time + interval, and a row is kept when it falls within
 * `windowDays` of now (0 = past due only). A history that cannot be read
 * is said, never swallowed: the value would otherwise vanish from the
 * list and read as "nothing due".
 */
export const dueRowsFor = Effect.fnUntraced(function* (input: {
  readonly client: MaruhiClient;
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly candidates: readonly MaxAgeCandidate[];
  readonly nowMs: number;
  readonly windowDays: number;
}): Effect.fn.Return<DueRows, never, CliIo> {
  const unreadable: string[] = [];
  const rows = yield* Effect.forEach(
    input.candidates,
    (candidate) =>
      input.client.variables
        .history({
          params: {
            projectId: input.projectId,
            environmentId: input.environmentId,
            variableId: candidate.variableId,
          },
        })
        .pipe(
          // A stalled read is bounded like a failed one: the note must
          // never hold `maruhi run` (B-7), and a check cannot wait forever
          Effect.timeout(HISTORY_TIMEOUT),
          Effect.map((response) => response.versions),
          // A failed read is noted and counted: the listing goes on, but
          // a check (`--fail-on-due`) cannot pass on an unknown age
          Effect.catch((error) =>
            Effect.as(
              logNote(
                `could not read the history of ${displayText(candidate.name)} in environment ${displayText(input.environmentId)} (${error.message}) — its age is not shown`,
              ),
              null,
            ),
          ),
          Effect.map((history): DueRow | null => {
            if (history === null) {
              unreadable.push(candidate.name);
              return null;
            }
            const pushedAtMs = plaintextPushedAtMs(history);
            if (pushedAtMs === null) {
              return null;
            }
            const dueAtMs = pushedAtMs + candidate.maxAgeDays * DAY_MS;
            return dueAtMs - input.nowMs > input.windowDays * DAY_MS
              ? null
              : {
                  environmentId: input.environmentId,
                  variableId: candidate.variableId,
                  name: candidate.name,
                  maxAgeDays: candidate.maxAgeDays,
                  pushedAtMs,
                  dueAtMs,
                };
          }),
        ),
    // Every read at once: a handful of metadata GETs to one DO, so the
    // note costs one round-trip time whatever the count (and one bound)
    { concurrency: "unbounded" },
  );
  return {
    rows: rows
      .filter((row): row is DueRow => row !== null)
      .toSorted((a, b) => a.dueAtMs - b.dueAtMs || a.name.localeCompare(b.name)),
    unreadable,
    unreadableEnvironments: [],
  };
});

/** A history row as the age needs it (the lineage declaration included). */
interface AgeRow {
  readonly version: number;
  readonly pushedAtMs: number;
  readonly sameValueAs?: number | undefined;
}

/**
 * The push time of the **plaintext** the current version holds (B-9): a
 * re-encryption (`sameValueAs = version − 1` — the mandated one after a
 * member leaves) and a rollback (`sameValueAs` older) are new versions of
 * an old value, so the lineage is followed to its root before the age is
 * taken. Server-declared like every history row (advisory); the only
 * direction a lying server gains is "older".
 */
function plaintextPushedAtMs(history: readonly AgeRow[]): number | null {
  const byVersion = new Map(history.map((row) => [row.version, row]));
  let row = history.toSorted((a, b) => b.version - a.version)[0];
  if (row === undefined) {
    return null;
  }
  const seen = new Set<number>();
  while (row.sameValueAs !== undefined && !seen.has(row.version)) {
    seen.add(row.version);
    const parent = byVersion.get(row.sameValueAs);
    if (parent === undefined) {
      break;
    }
    row = parent;
  }
  return row.pushedAtMs;
}

/**
 * "expired 14 days ago" / "due in 8 days". The day count rounds the way
 * the `--due-within` filter counts: a value due in any part of a day is
 * "due in 1 day" (it is inside a 1-day window), and a value past its
 * date by less than a day is "expired today" (it is past due). So the
 * words never contradict the verdict printed under them.
 */
export function describeDue(row: DueRow, nowMs: number): string {
  if (row.dueAtMs <= nowMs) {
    const days = Math.floor((nowMs - row.dueAtMs) / DAY_MS);
    return days === 0 ? "expired today" : `expired ${countNoun(days, "day")} ago`;
  }
  return `due in ${countNoun(Math.ceil((row.dueAtMs - nowMs) / DAY_MS), "day")}`;
}

/**
 * The one-line note of `maruhi run` / `maruhi pull` (S-E): only values
 * **past** their max age, each with the interval, the push date, and how
 * long ago it expired. Null when nothing is past due (the note exists
 * only when there is something to do). The next step is one pointer to
 * `rotation list`, which names the exact command per variable.
 */
function formatPastDueNote(rows: readonly DueRow[], nowMs: number): string | null {
  const expired = rows.filter((row) => row.dueAtMs <= nowMs);
  if (expired.length === 0) {
    return null;
  }
  const items = expired.map(
    (row) =>
      `${displayText(row.name)} (max age ${row.maxAgeDays}d, pushed ${formatUtcDate(row.pushedAtMs)}, ${describeDue(row, nowMs)})`,
  );
  const one = expired.length === 1;
  return `${countNoun(expired.length, "value")} past the max age ${one ? "its schema declares" : "their schemas declare"}: ${items.join(", ")} — rotate ${one ? "it" : "them"} (\`maruhi rotation list\` shows the next step for each)`;
}

/**
 * The point-of-use nudge (PF7a S-E): after `maruhi run` / `maruhi pull`
 * decrypted an environment, one note names the values past their max age.
 * Only variables whose verified statement declares an interval cost a
 * history call (concurrent); an environment with none costs nothing. The
 * note never changes the command's outcome.
 */
export const notePastDueValues = Effect.fn("max-age.notePastDueValues")(function* (input: {
  readonly client: MaruhiClient;
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly variables: readonly DecryptedVariable[];
}): Effect.fn.Return<void, never, CliIo> {
  const candidates = input.variables.flatMap((variable): MaxAgeCandidate[] =>
    variable.maxAgeDays === null
      ? []
      : [
          {
            variableId: variable.variableId,
            name: variable.name,
            maxAgeDays: variable.maxAgeDays,
          },
        ],
  );
  if (candidates.length === 0) {
    return;
  }
  const nowMs = yield* Clock.currentTimeMillis;
  const { rows } = yield* dueRowsFor({
    client: input.client,
    projectId: input.projectId,
    environmentId: input.environmentId,
    candidates,
    nowMs,
    windowDays: 0,
  });
  const note = formatPastDueNote(rows, nowMs);
  if (note !== null) {
    yield* logNote(note);
  }
});
