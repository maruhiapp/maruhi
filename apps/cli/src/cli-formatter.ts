import { ENVIRONMENT_ID_EXPECTED, PROJECT_ID_EXPECTED, VARIABLE_ID_EXPECTED } from "@maruhi/core";
import type { HelpDoc } from "effect/cli";
import { CliError, CliOutput } from "effect/cli";

import { AGENT_COMMAND_REQUIRED } from "./agent.ts";
import { formatNotice } from "./notice.ts";
import { RUN_COMMAND_REQUIRED } from "./run.ts";

export interface CommandSpec {
  readonly flags: readonly string[];
  readonly positionals: readonly string[];
  readonly subcommands?: readonly string[];
  readonly strayHint?: string;
}

export const NON_BLANK_MESSAGE = "a non-empty value (whitespace-only values are not accepted)";

export const PASSKEY_LABEL_MESSAGE =
  "1 to 64 characters without control or bidirectional-formatting characters";

const SAFE_EXPECTATIONS: ReadonlySet<string> = new Set([
  NON_BLANK_MESSAGE,
  PASSKEY_LABEL_MESSAGE,
  ENVIRONMENT_ID_EXPECTED,
  PROJECT_ID_EXPECTED,
  VARIABLE_ID_EXPECTED,
]);

const GLOBAL_FLAGS = ["--help", "--version"] as const;

function bareName(name: string): string {
  return name.replace(/^-+/, "");
}

function commandLabel(commandKey: string): string {
  return commandKey === "" ? "maruhi" : `maruhi ${commandKey}`;
}

function unrecognizedOptionMessage(
  error: CliError.UnrecognizedOption,
  specs: Readonly<Record<string, CommandSpec>>,
  commandKey: string,
): string {
  const errorKey = (error.command ?? []).slice(1).join(" ");
  const spec = specs[errorKey] ?? specs[commandKey];
  const errorCommandKey = specs[errorKey] !== undefined ? errorKey : commandKey;
  const option = bareName(error.option);
  if (spec?.positionals.includes(option) === true) {
    return `--${option} is a positional argument (it cannot be written as a flag). Write the value as a positional argument instead`;
  }
  if (spec?.flags.includes(option) === true) {
    return `Unknown flag position (--${option} belongs after the subcommand — e.g. ${commandLabel(errorCommandKey)} --${option} …)`;
  }
  const guess = error.suggestions[0];
  if (guess !== undefined) {
    return `Unknown flag (did you mean --${bareName(guess)}?)`;
  }
  return undeclaredFlagMessage(spec, errorCommandKey);
}

function undeclaredFlagMessage(spec: CommandSpec | undefined, commandKey: string): string {
  const subcommands = (spec?.flags.length ?? 0) === 0 ? (spec?.subcommands ?? []) : [];
  const first = subcommands[0];
  if (first !== undefined) {
    return `Unknown flag (${commandLabel(commandKey)} itself takes only ${GLOBAL_FLAGS.join(" / ")} — write the subcommand first and its flags after it, e.g. ${commandLabel(commandKey)} ${first} --flag …)`;
  }
  const declared = [...(spec?.flags ?? []).map((name) => `--${name}`), ...GLOBAL_FLAGS];
  return `Unknown flag (flags this command accepts: ${declared.join(" ")})`;
}

function isMissingRunCommand(error: CliError.MissingArgument, commandKey: string): boolean {
  return bareName(error.argument) === "command" && RUN_SHAPED_COMMANDS.has(commandKey);
}

const RUN_SHAPED_COMMANDS: ReadonlySet<string> = new Set(["run", "ci run", "proxy run", "agent"]);

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

function invalidValueMessage(error: CliError.InvalidValue, commandKey: string): string {
  const name = bareName(error.option);
  if (error.expected.includes("at most")) {
    return `Flag --${name} was specified more than once. Which occurrence you meant cannot be determined, so the invocation is rejected — write it exactly once`;
  }
  if (
    error.expected.includes("at least") ||
    error.expected === RUN_COMMAND_REQUIRED ||
    error.expected === AGENT_COMMAND_REQUIRED
  ) {
    return commandKey === "agent" ? AGENT_COMMAND_REQUIRED : RUN_COMMAND_REQUIRED;
  }
  const expectation = error.expected
    .replace("Schema validation failed: ", "")
    .replace(/^Expected /, "");
  const detail = SAFE_EXPECTATIONS.has(expectation) ? ` (expected: ${expectation})` : "";
  return error.kind === "argument"
    ? `Unacceptable value for positional argument ${name}${detail}`
    : `Unacceptable value for flag --${name}${detail}`;
}

function userErrorMessage(error: CliError.UserError): string {
  const authored = error.userMessage ?? "";
  return authored === "" ? "Invalid command-line arguments" : authored;
}

function unknownSubcommandMessage(
  error: CliError.UnknownSubcommand,
  specs: Readonly<Record<string, CommandSpec>>,
): string {
  const guess = error.suggestions[0];
  if (guess !== undefined) {
    return `Unknown subcommand (did you mean ${guess}?)`;
  }
  const parentKey = (error.parent ?? []).slice(1).join(" ");
  const known = specs[parentKey]?.subcommands ?? [];
  const listed = known.length === 0 ? "" : ` (expected one of: ${known.join(" | ")})`;
  return `Unknown subcommand${listed}`;
}

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
  if (error instanceof CliError.ValidationError) {
    return error.message;
  }
  return "Invalid command-line arguments";
}

function maruhiFormatter(
  commandKey: string,
  specs: Readonly<Record<string, CommandSpec>>,
  helpRequested: boolean,
  colors: boolean,
): CliOutput.Formatter {
  const describe = (error: CliError.CliError): string =>
    formatNotice("error", describeError(error, commandKey, specs), colors);
  const fallback = CliOutput.defaultFormatter({ colors });
  const spec = specs[commandKey];
  const ownParams = (spec?.flags.length ?? 0) + (spec?.positionals.length ?? 0);
  const optionalSubcommand = ownParams > 0 && (spec?.subcommands?.length ?? 0) > 0;
  const terminatorRequired = RUN_SHAPED_COMMANDS.has(commandKey);
  const adjustUsage = (text: string): string => {
    const withSubcommand = optionalSubcommand ? text.replace("<subcommand>", "[subcommand]") : text;
    return terminatorRequired
      ? withSubcommand.replace("<command...>", "-- <command...>")
      : withSubcommand;
  };
  return {
    formatHelpDoc: (doc: HelpDoc.HelpDoc) =>
      adjustUsage(helpRequested ? fallback.formatHelpDoc(doc) : `Usage: ${doc.usage}`),
    formatVersion: (_name: string, version: string) => version,
    formatError: describe,
    formatCliError: describe,
    formatErrors: (errors: ReadonlyArray<CliError.CliError>) => {
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

export function formatterLayer(
  commandKey: string,
  specs: Readonly<Record<string, CommandSpec>>,
  helpRequested: boolean,
  colors: boolean,
) {
  return CliOutput.layer(maruhiFormatter(commandKey, specs, helpRequested, colors));
}
