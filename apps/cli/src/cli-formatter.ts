// Implement maruhi's diagnostics **as an Effect mechanism
// (`CliOutput.Formatter`)** (ADR-0016 decision 3). The wording is English
// (ADR-0017).
//
// Why a replacement is needed: effect/unstable/cli's default wording
// **contains the typed value as-is** (`Invalid value for flag --env: "  "` /
// `Unexpected positional argument: "..."`). A positional argument or option
// value may hold plaintext (the `maruhi push API_KEY "$SECRET"` shape), so
// with the default, plaintext would flow to stderr → CI / agent logs.
//
// Why a Formatter and **not runner-side custom rendering**: the rendering
// call is owned by effect/unstable/cli itself (`showHelp` → `Console`).
// Plugging in a Formatter keeps that path while putting **only the
// wording** into maruhi's vocabulary. Adding ifs to the runner leaves a
// path that slips through whenever upstream adds a rendering.
//
// Only **our own vocabulary** may be shown: declared names, suggestions,
// counts. The dangerous fields are `UnexpectedArgument.arguments` and
// `InvalidValue.value`, and **`InvalidValue.expected`**: upstream's
// `Param.filter` builds `expected: onNone(a)`, so writing `onNone` with the
// value embedded (effect's own JSDoc example is
// `Expected even number, got ${n}`) leaks plaintext from the expectation
// side. Show it **only when it matches wording we wrote**.

import type { HelpDoc } from "effect/unstable/cli";
import { CliError, CliOutput } from "effect/unstable/cli";

import { AGENT_COMMAND_REQUIRED } from "./agent.ts";
import { formatNotice } from "./notice.ts";
import { RUN_COMMAND_REQUIRED } from "./run.ts";

/**
 * The command declarations used to build diagnostic wording (the check
 * itself lives on the Flag / Argument side).
 *
 * The contents are **derived from the command definitions themselves** by
 * effect-cli.ts (no hand-written copy — so that adding a declaration never
 * leaves only the diagnostics stale).
 */
export interface CommandSpec {
  readonly flags: readonly string[];
  readonly positionals: readonly string[];
  /** The list of subcommand names for a stage with nested subcommands (leaves omit it). */
  readonly subcommands?: readonly string[];
  /**
   * A command-specific fix attached to the rejection of extra positional
   * arguments (push's stdin guidance). Since the contents are withheld, a
   * mistyped invocation cannot be fixed without a fix hint (the discipline
   * the old cases of args.test.ts pinned).
   */
  readonly strayHint?: string;
}

/** The wording of the Schema that refuses an empty or whitespace-only value (the declaration side and here share the same constant). */
export const NON_BLANK_MESSAGE = "a non-empty value (whitespace-only values are not accepted)";

/**
 * The complete set of `expected` values that may be shown as-is.
 *
 * Wording not listed here **was not written by us** (= may contain a
 * value) and is not shown.
 */
/** The wording of the passkey label's accepted shape (paired with api-schema's PASSKEY_LABEL_PATTERN). */
export const PASSKEY_LABEL_MESSAGE =
  "1 to 64 characters without control or bidirectional-formatting characters";

const SAFE_EXPECTATIONS: ReadonlySet<string> = new Set([NON_BLANK_MESSAGE, PASSKEY_LABEL_MESSAGE]);

/** The built-in global flags (CliConfig's builtIns — absent from the declaration table). */
const GLOBAL_FLAGS = ["--help", "--version"] as const;

function bareName(name: string): string {
  return name.replace(/^-+/, "");
}

/** The command name for display (the root stage — the empty key — is `maruhi` alone). */
function commandLabel(commandKey: string): string {
  return commandKey === "" ? "maruhi" : `maruhi ${commandKey}`;
}

function unrecognizedOptionMessage(
  error: CliError.UnrecognizedOption,
  specs: Readonly<Record<string, CommandSpec>>,
  commandKey: string,
): string {
  // The declaration choice prefers **the stage upstream reported**
  // (`error.command` — at which stage the flag was undeclared). The
  // dispatch key is inferred from argv, so even a flag **written on the
  // parent stage** like `maruhi env --new-epoch rotate dev` resolves to the
  // leaf (`env rotate`), producing the self-contradictory diagnostic that
  // lists a refused flag among "the flags it accepts". When the parent
  // stage's declaration resolves, the guidance correctly forks to
  // placement (after the subcommand)
  const errorKey = (error.command ?? []).slice(1).join(" ");
  // root (empty errorKey) is also built from root's spec (the empty key):
  // for the shape where a flag is written before the command name, like
  // `maruhi --show pull`, falling back to the dispatched leaf's
  // (commandKey) declaration produces the self-contradictory diagnostic of
  // "refusing --show while listing it among the accepted". The root spec
  // forks to the placement guidance (after the subcommand)
  const spec = specs[errorKey] ?? specs[commandKey];
  const errorCommandKey = specs[errorKey] !== undefined ? errorKey : commandKey;
  // The shape that wrote a positional argument's name as an option needs a different fix
  const option = bareName(error.option);
  if (spec?.positionals.includes(option) === true) {
    return `--${option} is a positional argument (it cannot be written as a flag). Write the value as a positional argument instead`;
  }
  // A flag **present** in the resolved stage's declaration reported as
  // undeclared = it was written before the subcommand
  // (`audit --limit 5 list` — upstream does not inherit a parent's local
  // flags into the subcommand). Say neither "does not exist" nor "the
  // accepted list" — that is the self-contradictory diagnostic of refusing
  // a flag while listing it. Guide the placement only
  if (spec?.flags.includes(option) === true) {
    return `Unknown flag position (--${option} belongs after the subcommand — e.g. ${commandLabel(errorCommandKey)} --${option} …)`;
  }
  const guess = error.suggestions[0];
  if (guess !== undefined) {
    return `Unknown flag (did you mean --${bareName(guess)}?)`;
  }
  return undeclaredFlagMessage(spec, errorCommandKey);
}

/** The wording for an undeclared flag with no suggestion (the fix differs by stage kind — parent / leaf). */
function undeclaredFlagMessage(spec: CommandSpec | undefined, commandKey: string): string {
  // A nested stage (a parent holding subcommands) **usually** has no flags
  // of its own. Do not lie "the flag does not exist" to a user who wrote a
  // flag before the operation name — guide the **placement**. The exception
  // is a stage where the parent itself has a declaration (bare `audit` =
  // list); that one lists the accepted flags like a leaf
  const subcommands = (spec?.flags.length ?? 0) === 0 ? (spec?.subcommands ?? []) : [];
  const first = subcommands[0];
  if (first !== undefined) {
    return `Unknown flag (${commandLabel(commandKey)} itself takes only ${GLOBAL_FLAGS.join(" / ")} — write the subcommand first and its flags after it, e.g. ${commandLabel(commandKey)} ${first} --flag …)`;
  }
  // The globals admixed at run time (--help / --version) do not appear in
  // the declaration table, so they are filled in here (otherwise a real
  // flag falls out of the list)
  const declared = [...(spec?.flags ?? []).map((name) => `--${name}`), ...GLOBAL_FLAGS];
  return `Unknown flag (flags this command accepts: ${declared.join(" ")})`;
}

/**
 * When an `atLeast(1)` command got 0 arguments (rc.117's
 * `MissingArgument`). The wording differs between run / ci run and agent.
 * Not used for other missing arguments.
 */
function isMissingRunCommand(error: CliError.MissingArgument, commandKey: string): boolean {
  return (
    bareName(error.argument) === "command" &&
    (commandKey === "run" || commandKey === "ci run" || commandKey === "agent")
  );
}

function unexpectedArgumentMessage(
  error: CliError.UnexpectedArgument,
  spec: CommandSpec | undefined,
  commandKey: string,
): string {
  const takesNone = spec === undefined || spec.positionals.length === 0;
  const shape = takesNone
    ? `${commandLabel(commandKey)} takes no positional arguments`
    : `${commandLabel(commandKey)} only takes these positional arguments: ${spec.positionals.join(" ")}`;
  return `Unexpected extra arguments (${error.arguments.length}; contents not shown — they may contain plaintext values). ${shape}${spec?.strayHint ?? ""}`;
}

/**
 * Describing a value-carrying `InvalidValue` **without showing the
 * value**.
 *
 * `expected` is not necessarily safe just for being the declaration
 * side's vocabulary (as above, `Param.filter` makes `onNone(a)` itself
 * the `expected`). Only upstream's fixed phrases (`at most` / `at least`)
 * and **constants we wrote** can be trusted.
 */
function invalidValueMessage(error: CliError.InvalidValue, commandKey: string): string {
  const name = bareName(error.option);
  if (error.expected.includes("at most")) {
    return `Flag --${name} was specified more than once. Which occurrence you meant cannot be determined, so the invocation is rejected — write it exactly once`;
  }
  // "No command after `--`" is the same shape for run and agent. The example differs per stage
  if (
    error.expected.includes("at least") ||
    error.expected === RUN_COMMAND_REQUIRED ||
    error.expected === AGENT_COMMAND_REQUIRED
  ) {
    return commandKey === "agent" ? AGENT_COMMAND_REQUIRED : RUN_COMMAND_REQUIRED;
  }
  const expectation = error.expected.replace("Schema validation failed: ", "");
  const detail = SAFE_EXPECTATIONS.has(expectation) ? ` (expected: ${expectation})` : "";
  return error.kind === "argument"
    ? `Unacceptable value for positional argument ${name}${detail}`
    : `Unacceptable value for flag --${name}${detail}`;
}

/**
 * A `UserError` is shown **only when it is our written `userMessage`**.
 *
 * When `userMessage` is empty, `message` falls back to **`cause`'s
 * message** (per upstream's declaration). `cause` is any failure passed
 * to `Flag.mapEffect` / `Argument.mapEffect`, so it may contain the typed
 * value — for the same reason `InvalidValue.expected` is plugged by
 * {@link SAFE_EXPECTATIONS}, it is not passed through.
 *
 * The current declarations (effect-cli.ts) do not use `mapEffect`, so
 * this is unreachable — but it is a position where **a hole opens the
 * moment one is added**, so it is bound here.
 */
function userErrorMessage(error: CliError.UserError): string {
  const authored = error.userMessage ?? "";
  return authored === "" ? "Invalid command-line arguments" : authored;
}

/**
 * Unknown subcommand. Show the suggestion (edit distance) if any,
 * otherwise **the list of subcommands that stage takes** (do not make the
 * user hunt for where to fix a typo).
 */
function unknownSubcommandMessage(
  error: CliError.UnknownSubcommand,
  specs: Readonly<Record<string, CommandSpec>>,
): string {
  const guess = error.suggestions[0];
  if (guess !== undefined) {
    return `Unknown subcommand (did you mean ${guess}?)`;
  }
  // Pull the subcommand list from the parent stage's (`["maruhi", "env"]` → `env`) declaration
  const parentKey = (error.parent ?? []).slice(1).join(" ");
  const known = specs[parentKey]?.subcommands ?? [];
  const listed = known.length === 0 ? "" : ` (expected one of: ${known.join(" | ")})`;
  return `Unknown subcommand${listed}`;
}

/**
 * Renders one CLI error in maruhi's vocabulary, never echoing typed values.
 *
 * Discrimination is by instanceof (direct access to `_tag` is banned by
 * oxlint — the same discipline as src/failure.ts).
 */
export function describeError(
  error: CliError.CliError,
  commandKey: string,
  specs: Readonly<Record<string, CommandSpec>>,
): string {
  const spec = specs[commandKey];
  if (error instanceof CliError.UnrecognizedOption) {
    return unrecognizedOptionMessage(error, specs, commandKey);
  }
  if (error instanceof CliError.UnexpectedArgument) {
    return unexpectedArgumentMessage(error, spec, commandKey);
  }
  if (error instanceof CliError.InvalidValue) {
    return invalidValueMessage(error, commandKey);
  }
  if (error instanceof CliError.MissingArgument) {
    // rc.117: `Argument.atLeast(n)` with 0 is `MissingArgument`, not
    // `InvalidValue` ("at least"). run / ci run / agent's command reverts
    // to the "no command after `--`" wording. Other positional arguments
    // are shown as missing.
    if (isMissingRunCommand(error, commandKey)) {
      return commandKey === "agent" ? AGENT_COMMAND_REQUIRED : RUN_COMMAND_REQUIRED;
    }
    return `Missing positional argument ${bareName(error.argument)}`;
  }
  if (error instanceof CliError.MissingOption) {
    return `Missing required flag --${bareName(error.option)}`;
  }
  if (error instanceof CliError.UnknownSubcommand) {
    return unknownSubcommandMessage(error, specs);
  }
  if (error instanceof CliError.UserError) {
    return userErrorMessage(error);
  }
  return "Invalid command-line arguments";
}

/**
 * Builds the `CliOutput.Formatter` used by maruhi.
 *
 * `helpRequested` changes the amount of body text: an invocation with
 * explicit `--help` gets the default formatter's full text (help is
 * maruhi's output, not a diagnostic); a usage mistake gets **only the
 * single usage line** attached. A full help dump per mistake would bury
 * the diagnostic that matters.
 */
function maruhiFormatter(
  commandKey: string,
  specs: Readonly<Record<string, CommandSpec>>,
  helpRequested: boolean,
  colors: boolean,
): CliOutput.Formatter {
  // Rendering the failure prefix `maruhi:` is shared with notice.ts (color applies to the prefix only)
  const describe = (error: CliError.CliError): string =>
    formatNotice("error", describeError(error, commandKey, specs), colors);
  // Full help rides upstream's default formatter (bold headings, colors
  // for usage / flag names). Only the color decision is passed — upstream's
  // auto-detection (`process.stdout.isTTY` and `NO_COLOR === "1"`) looks at
  // stdout and also disagrees with the NO_COLOR convention (disabled when
  // non-empty), so it is overridden by maruhi's decision (shouldUseColor —
  // stderr-based)
  const fallback = CliOutput.defaultFormatter({ colors });
  // On a parent whose bare invocation runs a handler (audit = list), the
  // subcommand is not required. Upstream's usage uniformly renders
  // `<subcommand>` (required), so it is corrected to `[subcommand]`. The
  // decision is declaration-driven (a stage holding both its own
  // declaration [flag or positional] and subcommands = only the
  // handler-bearing parents [audit / schema / agent] qualify; root and
  // ordinary parents — empty declarations — are untouched)
  const spec = specs[commandKey];
  const ownParams = (spec?.flags.length ?? 0) + (spec?.positionals.length ?? 0);
  const optionalSubcommand = ownParams > 0 && (spec?.subcommands?.length ?? 0) > 0;
  // `run` requires `--` (ADR-0016 decision 8), yet upstream's usage
  // renders it only as a variadic positional `<command...>`. The usage
  // shows how it is written (ruling F). The substitution touches only the
  // usage line's word, and the decision uses the declaration-derived key
  const terminatorRequired =
    commandKey === "run" || commandKey === "ci run" || commandKey === "agent";
  const adjustUsage = (text: string): string => {
    const withSubcommand = optionalSubcommand ? text.replace("<subcommand>", "[subcommand]") : text;
    return terminatorRequired
      ? withSubcommand.replace("<command...>", "-- <command...>")
      : withSubcommand;
  };
  return {
    formatHelpDoc: (doc: HelpDoc.HelpDoc) =>
      adjustUsage(helpRequested ? fallback.formatHelpDoc(doc) : `Usage: ${doc.usage}`),
    // `--version` prints **the version number only** (pinned by
    // version.test.ts. The shape usable as-is in `V=$(maruhi --version)`)
    formatVersion: (_name: string, version: string) => version,
    formatError: describe,
    formatCliError: describe,
    // On an invocation whose command name did not resolve, flags are
    // reconciled against root's declarations, so even correctly spelled
    // flags line up as unknown. The mistake is in the command name — do
    // not make the user hunt through correctly-spelled flags
    formatErrors: (errors: ReadonlyArray<CliError.CliError>) => {
      // Suppress only at the **root stage** (an invocation whose command
      // name itself did not resolve): on a deep-stage UnknownSubcommand
      // (the abc of `server abc`), placement guidance for flags written on
      // the parent stage is still needed alongside
      const commandNotFound = errors.some(
        (error) => error instanceof CliError.UnknownSubcommand && (error.parent ?? []).length <= 1,
      );
      const shown = commandNotFound
        ? errors.filter((error) => !(error instanceof CliError.UnrecognizedOption))
        : errors;
      return shown.map(describe).join("\n");
    },
  };
}

/** Provides {@link maruhiFormatter} as a layer (`CliOutput.layer`). */
export function formatterLayer(
  commandKey: string,
  specs: Readonly<Record<string, CommandSpec>>,
  helpRequested: boolean,
  colors: boolean,
) {
  return CliOutput.layer(maruhiFormatter(commandKey, specs, helpRequested, colors));
}
