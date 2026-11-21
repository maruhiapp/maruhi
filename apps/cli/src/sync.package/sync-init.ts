import { type ProjectId } from "@maruhi/core";
import { Effect } from "effect";

import { type CliError, usageError } from "../errors.ts";
import { CliIo } from "../io.ts";
import { logNote } from "../notice.ts";
import { parseSyncConfig } from "./sync-config.ts";
import { defaultDriverOf, isUnavailable, SYNC_PRESETS } from "./sync-preset.ts";
import type { DriverKind, OptionSpec, PresetId } from "./sync-types.ts";

interface SyncInitInput {
  readonly target: string;
  readonly preset: string;
  readonly driver: string | undefined;
  readonly environment: string;
  readonly receipts: string;
  readonly project: ProjectId | undefined;
  readonly variables: string | undefined;
  readonly exclude: string | undefined;
  readonly production: boolean;
  readonly cwd: string | undefined;
  readonly command: string | undefined;
  readonly tokenEnvironment: string | undefined;
  readonly tokenName: string | undefined;
  readonly onPush: string | undefined;
  readonly workflow: string | undefined;
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

function compact(record: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(record).filter(([, value]) => value !== undefined));
}

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

const buildSyncConfigJson = Effect.fn("sync-init.buildSyncConfigJson")(function* (
  input: SyncInitInput,
): Effect.fn.Return<string, CliError> {
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
  const parsed = parseSyncConfig(json, ".");
  if (typeof parsed === "string") {
    return yield* Effect.fail(usageError(`The config would be invalid: ${parsed}`));
  }
  return json;
});

export const syncInitOp = Effect.fn("sync-init.syncInitOp")(function* (
  input: SyncInitInput,
): Effect.fn.Return<void, CliError, CliIo> {
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
