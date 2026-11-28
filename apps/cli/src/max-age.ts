import { type EnvironmentId, type ProjectId, type VariableId } from "@maruhi/core";
import { Clock, Duration, Effect } from "effect";

import type { MaruhiClient } from "./api.ts";
import { countNoun, displayText, formatUtcDate } from "./display.ts";
import type { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";

export const DAY_MS = 24 * 60 * 60 * 1000;
export const DUE_SOON_DAYS = 14;
export const MAX_PROPOSAL_DAYS = 30;

export interface MaxAgeCandidate {
  readonly variableId: VariableId;
  readonly name: string;
  readonly maxAgeDays: number;
}

export interface DueRow {
  readonly environmentId: EnvironmentId;
  readonly variableId: VariableId;
  readonly name: string;
  readonly maxAgeDays: number;
  readonly pushedAtMs: number;
  readonly dueAtMs: number;
}

export interface DueRows {
  readonly rows: readonly DueRow[];
  readonly unreadable: readonly string[];
  readonly unreadableEnvironments: readonly string[];
}

const HISTORY_TIMEOUT = Duration.seconds(10);

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
          Effect.timeout(HISTORY_TIMEOUT),
          Effect.map((response) => response.versions),
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

interface AgeRow {
  readonly version: number;
  readonly pushedAtMs: number;
  readonly sameValueAs?: number | undefined;
}

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

export function describeDue(row: DueRow, nowMs: number): string {
  if (row.dueAtMs <= nowMs) {
    const days = Math.floor((nowMs - row.dueAtMs) / DAY_MS);
    return days === 0 ? "expired today" : `expired ${countNoun(days, "day")} ago`;
  }
  return `due in ${countNoun(Math.ceil((row.dueAtMs - nowMs) / DAY_MS), "day")}`;
}

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

export const notePastDueValues = Effect.fn("max-age.notePastDueValues")(function* (input: {
  readonly client: MaruhiClient;
  readonly projectId: ProjectId;
  readonly environmentId: EnvironmentId;
  readonly variables: readonly {
    readonly variableId: VariableId;
    readonly name: string;
    readonly maxAgeDays: number | null;
  }[];
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
