// `maruhi sync init <target>`: generating the repository config
// (`maruhi.sync.json`) (SY2 stage 2 — ruling F).
//
// The precedent is `maruhi project anchor` (anchor.ts): emit the
// non-secret config **as JSON to stdout** and let the user redirect
// and commit it. No file is written (the CLI is not given the
// overwrite/merge judgment on an existing file — a second target is
// added by hand. The docs table explains the keys). It does not go
// to the network either: every input is a flag, and before emitting
// it confirms the product passes sync-config.ts's strict parser
// **unchanged** (if it does not, the write-up error is reported
// with a reason = 2).
//
// Value defaults: `variables` is `"all"` when omitted (+ a Note
// guiding to exclude public-config / platform-owned resources —
// supplement 13 W3), and `production` defers to the preset's
// judgment (the explicit form is `--production`).

import { Effect } from "effect";

import { type CliError, usageError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";
import { parseSyncConfig } from "./sync-config.ts";
import { defaultDriverOf, isUnavailable, SYNC_PRESETS } from "./sync-preset.ts";
import type { DriverKind, OptionSpec, PresetId } from "./sync-types.ts";

/** `maruhi sync init`'s input (all from explicit flags). */
export interface SyncInitInput {
  readonly target: string;
  readonly preset: string;
  readonly driver: string | undefined;
  /** The source maruhi environment ID (`--env`). */
  readonly environment: string;
  /** The receipt environment ID (`--receipts`). */
  readonly receipts: string;
  readonly project: string | undefined;
  /** Comma-separated variable names (omitted = "all"). */
  readonly variables: string | undefined;
  /** Comma-separated exclusion names (only when `variables` is omitted). */
  readonly exclude: string | undefined;
  readonly production: boolean;
  readonly cwd: string | undefined;
  readonly command: string | undefined;
  readonly tokenEnvironment: string | undefined;
  readonly tokenName: string | undefined;
  /** The post-push sync (`--on-push apply|workflow` — stage 3). */
  readonly onPush: string | undefined;
  /** The workflow filename for `--on-push workflow` (`--workflow`). */
  readonly workflow: string | undefined;
  /** A list of `key=value` (`--option`). Boolean options are true / false. */
  readonly options: readonly string[];
}

function splitList(value: string | undefined): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/** Interprets `--option key=value` (maps to boolean per the declaration's type). */
function parseOptionFlags(
  given: readonly string[],
  declared: Readonly<Record<string, OptionSpec>>,
): Record<string, string | boolean> | CliError {
  const options: Record<string, string | boolean> = {};
  for (const entry of given) {
    const separator = entry.indexOf("=");
    if (separator <= 0) {
      return usageError(
        `--option takes key=value (accepted keys for this preset and driver: ${Object.keys(declared).join(", ")})`,
      );
    }
    const key = entry.slice(0, separator);
    const value = entry.slice(separator + 1);
    const spec = Object.hasOwn(declared, key) ? declared[key] : undefined;
    if (spec === undefined) {
      return usageError(
        `--option names an unknown key (accepted keys for this preset and driver: ${Object.keys(declared).join(", ")})`,
      );
    }
    if (spec.type === "boolean") {
      if (value !== "true" && value !== "false") {
        return usageError(`--option ${key} takes true or false`);
      }
      options[key] = value === "true";
    } else {
      options[key] = value;
    }
  }
  return options;
}

/** Omitted keys do not appear in the JSON (drops `undefined` values). */
function compact(record: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(record).filter(([, value]) => value !== undefined));
}

/** One target's JSON object (key order matches the docs table). */
function targetObjectOf(
  input: SyncInitInput,
  driver: DriverKind,
  options: Record<string, string | boolean>,
): Record<string, unknown> {
  const variables = splitList(input.variables);
  const token =
    input.tokenEnvironment === undefined && input.tokenName === undefined
      ? undefined
      : { environment: input.tokenEnvironment, name: input.tokenName };
  return compact({
    preset: input.preset,
    // exec is the default for omitting. http is written explicitly even on a preset that only has it (a form where the plaintext's destination is readable)
    driver: driver === "exec" ? undefined : driver,
    environment: input.environment,
    variables: variables === undefined || variables.length === 0 ? "all" : variables,
    exclude: splitList(input.exclude),
    production: input.production ? true : undefined,
    cwd: input.cwd,
    command: input.command,
    token,
    options: Object.keys(options).length === 0 ? undefined : options,
    onPush: input.onPush,
    workflow: input.workflow === undefined ? undefined : { file: input.workflow },
  });
}

/** Assembles the config object, validates it through the strict parser, then serializes it to a JSON string. */
function buildSyncConfigJson(input: SyncInitInput): Effect.Effect<string, CliError> {
  return Effect.gen(function* () {
    if (!Object.hasOwn(SYNC_PRESETS, input.preset)) {
      return yield* Effect.fail(
        usageError(`--preset must be one of ${Object.keys(SYNC_PRESETS).join(", ")}`),
      );
    }
    const preset = SYNC_PRESETS[input.preset as PresetId];
    const driver = input.driver ?? defaultDriverOf(preset);
    if (driver !== "exec" && driver !== "http") {
      return yield* Effect.fail(
        usageError("--driver must be exec (the default when the preset has one) or http"),
      );
    }
    const declaration = driver === "exec" ? preset.exec : preset.http;
    if (isUnavailable(declaration)) {
      return yield* Effect.fail(
        usageError(
          `--driver ${driver}: ${declaration.unavailable}; use --driver ${defaultDriverOf(preset)}`,
        ),
      );
    }
    const options = parseOptionFlags(input.options, declaration.options);
    if (options instanceof Error) {
      return yield* Effect.fail(options);
    }
    const config = compact({
      version: 1,
      project: input.project,
      receipts: { environment: input.receipts },
      targets: { [input.target]: targetObjectOf(input, driver, options) },
    });
    const json = `${JSON.stringify(config, null, 2)}\n`;
    // The product passes the strict parser unchanged (if it does not, report the write-up error with a reason)
    const parsed = parseSyncConfig(json, ".");
    if (typeof parsed === "string") {
      return yield* Effect.fail(usageError(`The config would be invalid: ${parsed}`));
    }
    return json;
  });
}

/** `maruhi sync init`: emits the config JSON to stdout (the command's output — decision 9). */
export function syncInitOp(input: SyncInitInput): Effect.Effect<void, CliError, CliIo> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const json = yield* buildSyncConfigJson(input);
    yield* io.log(json.trimEnd());
    if (input.variables === undefined) {
      yield* logNote(
        'the target copies every variable of the environment ("all"). Keep public configuration and platform-owned resources out with "exclude", or list the names to copy in "variables"',
      );
    }
    const preset = SYNC_PRESETS[input.preset as PresetId];
    if ((input.driver ?? defaultDriverOf(preset)) === "http") {
      yield* logNote(
        `the http driver reads the vendor's token from the maruhi variable named in "token". Push it there before the first apply, and give the token the least permission the target needs (see the Deploy targets page in the docs)`,
      );
    } else if (!isUnavailable(preset.exec) && preset.exec.signInHint !== undefined) {
      yield* logNote(preset.exec.signInHint);
    }
    if (input.project === undefined) {
      yield* logNote(
        'add "project": "<project ID>" to pin the config to one project (`maruhi sync` then refuses a --project flag that names another)',
      );
    }
    if (input.onPush === "workflow") {
      yield* logNote(
        `the workflow must have a workflow_dispatch trigger with a "target" input and run \`maruhi ci sync\` for it (see the Deploy targets page in the docs). \`maruhi push\` triggers it with gh, which must be installed and signed in`,
      );
    }
  });
}
