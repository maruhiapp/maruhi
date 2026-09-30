// Vocabulary and rendering of stderr notices (Note / Warning /
// failure) (DP5 rulings A / B).
//
// Vocabulary (distinguish by purpose — never mix):
//   - `Note:`     information. The command succeeded, and what is
//                 written is an optional next step or an
//                 explanation of the state. Missing it does not
//                 lower safety
//   - `Warning:`  degraded / attention. The command continued (or
//                 succeeded) but there is a state the user should
//                 check. Anything whose miss can lower safety always
//                 goes here (floor corruption, anchor mismatch,
//                 signature-verification failure, etc.)
//   - `maruhi:`   failure (exit code ≠ 0). The wording is "what
//                 happened. The next step"
//
// Every destination is stderr (ADR-0016 decision 9 — stdout carries
// only the command's output). Rather than scattering string
// concatenation `\`Note: ${…}\`` around, prefix rendering gathers in
// this one place.
//
// Color discipline (ruling A): only the **prefix** is colored. The
// body (which may contain values, identifiers, URLs) is never
// colored — limiting the colored thing to a constant prefix
// structurally prevents color from mixing into identifiers or
// values. No symbols (✓ / ⚠ etc.) are used (avoids mojibake on
// Windows terminals and non-UTF-8 locales; the prefix word carries
// that role). Whether color is allowed is `CliIo.colorEnabled()` —
// production is {@link shouldUseColor} (whether stderr is a
// terminal + NO_COLOR / FORCE_COLOR / TERM=dumb); tests default to
// no color. The decision material is taken via the service;
// `process.*` is not read here (ADR-0016 decision 5).

import { Context, Effect, Option } from "effect";

import { CliIo } from "./io.ts";

/**
 * The wordings of Notes / Warnings emitted within one command
 * execution (ruling C's rule "an identical notice appears at most
 * once per command run"). Prevents the same one line (e.g. a head
 * declaration's send failure) from appearing twice on executions
 * that traverse the same path twice, like sync → re-sync. This is
 * replaceable **state**, so it is a service, and runEffectCli
 * supplies a fresh ledger per execution (contexts without a ledger
 * — unit tests etc. — are not suppressed).
 */
export class NoticeLedger extends Context.Service<NoticeLedger, Set<string>>()(
  "cli/NoticeLedger",
) {}

/**
 * An optional observer of the notices a run emits, by kind and text (before
 * rendering). `maruhi mcp` uses it to return a read's warnings to the agent
 * as data (pf5-design.md §17 — a structured hook, not a parse of the rendered
 * line). Absent everywhere else: the notices only go to stderr.
 */
export class NoticeObserver extends Context.Service<
  NoticeObserver,
  (kind: NoticeKind, text: string) => void
>()("cli/NoticeObserver") {}

/** Kind of a stderr notice (decides the prefix and its color). */
export type NoticeKind = "note" | "warning" | "error";

const RESET = "\u001B[0m";
const PREFIXES: Readonly<Record<NoticeKind, { readonly label: string; readonly color: string }>> = {
  // info = cyan (the "information" convention of the terminal 16
  // colors. No imitation of the vermilion accent — a terminal's red
  // carries the meaning of danger)
  note: { label: "Note:", color: "\u001B[36m" },
  warning: { label: "Warning:", color: "\u001B[33m" },
  error: { label: "maruhi:", color: "\u001B[31m" },
};

/**
 * Decides whether stderr decorations (ANSI colors) may be used.
 *
 * Precedence: `FORCE_COLOR` (non-empty; `0` disables) > `NO_COLOR`
 * (non-empty disables — no-color.org's convention: the value does
 * not matter) > `TERM=dumb` > whether stderr is a terminal. stdout
 * is not used in the decision (only stderr's notices are colored;
 * stdout is data).
 */
export function shouldUseColor(input: {
  readonly stderrIsTerminal: boolean;
  readonly envVar: (name: string) => string | undefined;
}): boolean {
  const force = input.envVar("FORCE_COLOR");
  if (force !== undefined && force !== "") {
    return force !== "0";
  }
  const noColor = input.envVar("NO_COLOR");
  if (noColor !== undefined && noColor !== "") {
    return false;
  }
  if (input.envVar("TERM") === "dumb") {
    return false;
  }
  return input.stderrIsTerminal;
}

/**
 * Renders one notice line: the prefix (optionally colored) and the text.
 *
 * The caller passes a body string already neutralized via
 * `displayText` (the discipline of not passing server-derived
 * strings through raw is unchanged — only decoration is added
 * here).
 */
export function formatNotice(kind: NoticeKind, text: string, color: boolean): string {
  const prefix = PREFIXES[kind];
  const label = color ? `${prefix.color}${prefix.label}${RESET}` : prefix.label;
  return `${label} ${text}`;
}

/**
 * Where a notice belongs. `run` (default): a run-level fact, printed at most
 * once per command execution. `prompt`: attached to the interactive item
 * printed just above it (a candidate in `schema import`), so it repeats on
 * every retry of that item and is indented under it — never deduplicated.
 */
export interface NoticeOptions {
  readonly scope?: "run" | "prompt";
}

/** Writes a notice to stderr (dedupe by exact text within one run — `run` scope only). */
function logNotice(
  kind: NoticeKind,
  text: string,
  options: NoticeOptions,
): Effect.Effect<void, never, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const scope = options.scope ?? "run";
    const ledger = yield* Effect.serviceOption(NoticeLedger);
    if (kind !== "error" && scope === "run" && Option.isSome(ledger)) {
      const key = `${kind}\u0000${text}`;
      if (ledger.value.has(key)) {
        return;
      }
      ledger.value.add(key);
    }
    const observer = yield* Effect.serviceOption(NoticeObserver);
    if (Option.isSome(observer)) {
      observer.value(kind, text);
    }
    const line = formatNotice(kind, text, io.colorEnabled());
    yield* io.logError(scope === "prompt" ? `  ${line}` : line);
  });
}

/** Writes `Note: <text>` to stderr (information — the command succeeded). */
export function logNote(text: string, options: NoticeOptions = {}) {
  return logNotice("note", text, options);
}

/** Writes `Warning: <text>` to stderr (degraded or suspicious state — the command continued). */
export function logWarning(text: string, options: NoticeOptions = {}) {
  return logNotice("warning", text, options);
}

/** Writes `maruhi: <message>` to stderr (the command failed). */
export function logFailure(message: string) {
  return logNotice("error", message, {});
}
