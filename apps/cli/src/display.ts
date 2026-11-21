import { type ProjectId } from "@maruhi/core";
import { Effect, Redacted, type Stdio } from "effect";

import { ensureValueDisplayAllowed } from "./agent-gate.ts";
import { cliError, type CliError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logWarning } from "./notice.ts";

const ORDER_BREAKING =
  "\\u00AD\\u061C\\u180E\\u200B\\u200E\\u200F\\u202A-\\u202E\\u2060-\\u2064\\u2066-\\u2069\\u2028\\u2029\\uFEFF\\uFFF9-\\uFFFB";
const CONTROL_CHARS = new RegExp(`\\p{Cc}|[${ORDER_BREAKING}]`, "gu");
const ESCAPABLE = /[^\u0020-\u007E]|["\\]/gu;

export function displayText(value: string): string {
  return value.replace(CONTROL_CHARS, "\uFFFD");
}

const MAX_TIMESTAMP_MS = 8_640_000_000_000_000;

const STANDARD_ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function isoOf(ms: number): string | null {
  if (!Number.isFinite(ms) || Math.abs(ms) > MAX_TIMESTAMP_MS) {
    return null;
  }
  const iso = new Date(ms).toISOString();
  return STANDARD_ISO.test(iso) ? iso : null;
}

function invalidTimestamp(ms: number): string {
  return `(invalid timestamp: ${ms})`;
}

export function formatUtcSeconds(ms: number): string {
  const iso = isoOf(ms);
  return iso === null ? invalidTimestamp(ms) : iso.slice(0, 19).replace("T", " ") + " UTC";
}

export function formatUtcMinutes(ms: number): string {
  const iso = isoOf(ms);
  return iso === null ? invalidTimestamp(ms) : iso.slice(0, 16).replace("T", " ") + " UTC";
}

export function formatUtcDate(ms: number): string {
  const iso = isoOf(ms);
  return iso === null ? invalidTimestamp(ms) : iso.slice(0, 10);
}

export function countNoun(count: number, singular: string): string {
  return `${count} ${singular}${count === 1 ? "" : "s"}`;
}

export function describeProjects(projectIds: readonly ProjectId[]): string {
  return `${countNoun(projectIds.length, "project")} (${projectIds.map(displayText).join(", ")})`;
}

export function describeListed(count: number): string {
  return `no project the server lists for you (${count === 0 ? "none" : count} listed)`;
}

export function describeListedScope(count: number): string {
  return `the ${countNoun(count, "project")} the server lists for you`;
}

export function describeUnmarkedLedgerKey(): string {
  return "was not created as a reserve key (its ledger record does not carry the mark maruhi writes when it creates one), so it is not used as your reserve key";
}

export function escapeText(value: string): string {
  return value.replace(ESCAPABLE, (char) =>
    char === "\\" || char === '"'
      ? `\\${char}`
      : `\\u{${(char.codePointAt(0) ?? 0xff_fd).toString(16).padStart(4, "0")}}`,
  );
}

const VALUE_CONTROL_CHARS = new RegExp(`[^\\P{Cc}\\t\\n]|[${ORDER_BREAKING}]`, "gu");

function displayValue(value: string): string {
  return value.replace(VALUE_CONTROL_CHARS, "\uFFFD");
}

export interface DisplayableVariable {
  readonly name: string;
  readonly version: number;
  readonly epoch: number;
  readonly value: Redacted.Redacted<Uint8Array>;
}

export function formatPulledLine(variable: DisplayableVariable): string {
  const byteLength = Redacted.value(variable.value).byteLength;
  return `${displayText(variable.name)}\tversion=${variable.version}\tepoch=${variable.epoch}\t(${byteLength} bytes)`;
}

export function logWarnings(warnings: readonly string[]): Effect.Effect<void, never, CliIo> {
  return Effect.forEach(warnings, (warning) => logWarning(warning), { discard: true });
}

const strictValueDecoder = new TextDecoder("utf-8", { fatal: true });

export function decodeValueText(value: Uint8Array): string | null {
  try {
    return strictValueDecoder.decode(value);
  } catch {
    return null;
  }
}

export const showValues = Effect.fn("display.showValues")(function* (
  variables: readonly DisplayableVariable[],
): Effect.fn.Return<void, CliError, CliIo | Stdio.Stdio> {
  const io = yield* CliIo;
  yield* ensureValueDisplayAllowed;
  const lines: string[] = [];
  const altered: string[] = [];
  for (const variable of variables) {
    const text = decodeValueText(Redacted.value(variable.value));
    if (text === null) {
      return yield* Effect.fail(
        cliError(
          `The value of variable ${displayText(variable.name)} is not valid UTF-8 and cannot be displayed (binary values are outside the scope of --show)`,
        ),
      );
    }
    const shown = displayValue(text);
    if (shown !== text) {
      altered.push(displayText(variable.name));
    }
    lines.push(...renderValue(displayText(variable.name), shown));
  }
  for (const line of lines) {
    yield* io.log(line);
  }
  if (altered.length > 0) {
    yield* logWarning(warnAlteredDisplay(altered));
  }
});

const CONTINUATION = "| ";

function renderValue(name: string, shown: string): readonly string[] {
  const trailingNewline = shown.endsWith("\n");
  const parts = (trailingNewline ? shown.slice(0, -1) : shown).split("\n");
  if (parts.length === 1 && !trailingNewline) {
    return [`${name}=${shown}`];
  }
  const trailing = trailingNewline ? " with a trailing newline" : "";
  return [
    `${name}= (a ${parts.length}-line value${trailing}; the leading "${CONTINUATION}" on each line below is a marker added by maruhi)`,
    ...parts.map((line) => `${CONTINUATION}${line}`),
  ];
}

function warnAlteredDisplay(names: readonly string[]): string {
  return `the values of these variables contain characters unusable in terminal output (control characters or ordering-manipulation characters), shown as \uFFFD instead. The displayed strings do not match the actual values — do not copy and use them. To pass the actual values to a process, use \`maruhi run -- <command>\` (though values containing NUL cannot be passed as env vars, so run rejects them too): ${names.join(", ")}`;
}
