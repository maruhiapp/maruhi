import { dirname, join } from "node:path";

import { type EnvironmentId, type ProjectId } from "@maruhi/core";
import { Effect, Result, Schema } from "effect";

import {
  at,
  closedRecord,
  configHeader,
  decode,
  environmentId,
  field,
  type Invalid,
  knownKeys,
  loadConfig,
  nullishOr,
  objectLeaf,
  type Parsed,
  parseConfigDocument,
  refuse,
  stringLeaf,
  undefinedOr,
} from "../config-schema.ts";
import { type CliError, usageError } from "../errors.ts";
import { loadIfPresent } from "../json-record.ts";
import type { ExecPreset } from "./sync-exec.ts";
import type { HttpPreset } from "./sync-http.ts";
import { defaultDriverOf, isUnavailable, type SyncPreset, SYNC_PRESETS } from "./sync-preset.ts";
import {
  type DriverKind,
  type OptionSpec,
  PRESET_IDS,
  type PresetId,
  type ResolvedOptions,
} from "./sync-types.ts";

export const DEFAULT_SYNC_CONFIG_PATH = "maruhi.sync.json";

export interface TokenRef {
  readonly environment: EnvironmentId;
  readonly name: string;
}

export type TargetDriver =
  | {
      readonly kind: "exec";
      readonly spec: ExecPreset;
      readonly cwd: string;
      readonly command: string;
      readonly namedCommand: boolean;
    }
  | {
      readonly kind: "http";
      readonly spec: HttpPreset;
      readonly token: TokenRef;
    };

export type OnPush =
  | { readonly kind: "apply" }
  | {
      readonly kind: "workflow";
      readonly file: string;
      readonly ref: string | undefined;
      readonly command: string;
      readonly namedCommand: boolean;
      readonly cwd: string;
    };

export interface SyncTarget {
  readonly name: string;
  readonly preset: SyncPreset;
  readonly driver: TargetDriver;
  readonly environment: EnvironmentId;
  readonly variables: readonly string[] | "all";
  readonly exclude: readonly string[];
  readonly production: boolean;
  readonly options: ResolvedOptions;
  readonly onPush: OnPush | null;
}

export interface SyncConfig {
  readonly version: 1;
  readonly projectId: ProjectId | undefined;
  readonly receiptsEnvironment: EnvironmentId;
  readonly targets: ReadonlyMap<string, SyncTarget>;
}

const TARGET_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

const nonEmpty = (message: string) => stringLeaf(message, (value) => value.trim().length > 0);

const ghArgument = (message: string) =>
  stringLeaf(message, (value) => value.trim().length > 0 && !value.startsWith("-"));

const BOOLEAN_OPTION = Schema.Boolean.annotate({ message: " must be true or false" });
const STRING_OPTION = nonEmpty(" must be a non-empty string");

function parseOptionValue(spec: OptionSpec, given: unknown): Parsed<string | boolean> {
  if (spec.type === "boolean") {
    return decode(BOOLEAN_OPTION, given);
  }
  return Result.gen(function* () {
    const text = yield* decode(STRING_OPTION, given);
    if (spec.values !== undefined && !spec.values.includes(text)) {
      return yield* refuse(` must be one of ${spec.values.join(", ")}`);
    }
    if (spec.pattern !== undefined && !spec.pattern.regex.test(text)) {
      return yield* refuse(` must be ${spec.pattern.hint}`);
    }
    return text;
  });
}

const OPTIONS_MESSAGE = " must be an object";
const OPTIONS = undefinedOr(OPTIONS_MESSAGE, objectLeaf(OPTIONS_MESSAGE));

function parseTargetOptions(
  presetId: PresetId,
  driverKind: DriverKind,
  declaredOptions: Readonly<Record<string, OptionSpec>>,
  given: Readonly<Record<string, unknown>>,
): Parsed<ResolvedOptions> {
  const options = Result.gen(function* () {
    const declared = Object.keys(declaredOptions);
    yield* knownKeys(
      given,
      declared,
      `the ${presetId} preset with the ${driverKind} driver accepts: ${declared.join(", ")}`,
    );
    const resolved: Record<string, string | boolean> = {};
    for (const [key, spec] of Object.entries(declaredOptions)) {
      const value = given[key];
      if (value === undefined) {
        if (spec.required) {
          return yield* refuse(
            ` is required for the ${presetId} preset with the ${driverKind} driver${spec.values === undefined ? "" : ` (one of ${spec.values.join(", ")})`}`,
            [key],
          );
        }
        continue;
      }
      resolved[key] = yield* at([key], parseOptionValue(spec, value));
    }
    return resolved;
  });
  return at(["options"], options);
}

const TARGET_KEYS = [
  "preset",
  "driver",
  "environment",
  "variables",
  "exclude",
  "production",
  "cwd",
  "command",
  "token",
  "options",
  "onPush",
  "workflow",
] as const;

const VARIABLES_MESSAGE = ' must be a non-empty array of variable names, or "all"';
const VARIABLES_LIST = Schema.Array(nonEmpty(VARIABLES_MESSAGE))
  .annotate({ message: VARIABLES_MESSAGE })
  .check(Schema.isMinLength(1, { message: VARIABLES_MESSAGE }));

const EXCLUDE_MESSAGE = " must be an array of variable names";
const EXCLUDE_LIST = undefinedOr(
  EXCLUDE_MESSAGE,
  Schema.Array(nonEmpty(EXCLUDE_MESSAGE)).annotate({ message: EXCLUDE_MESSAGE }),
);

interface VariableSelection {
  readonly variables: readonly string[] | "all";
  readonly exclude: readonly string[];
}

function parseVariables(record: Record<string, unknown>): Parsed<VariableSelection> {
  return Result.gen(function* () {
    if (record["variables"] === "all") {
      const exclude = yield* field(record, "exclude", EXCLUDE_LIST);
      const all: VariableSelection = { variables: "all", exclude: exclude ?? [] };
      return all;
    }
    const names = yield* field(record, "variables", VARIABLES_LIST);
    if (record["exclude"] !== undefined) {
      return yield* refuse(' applies only when variables is "all"', ["exclude"]);
    }
    if (new Set(names).size !== names.length) {
      return yield* refuse(" lists the same name more than once", ["variables"]);
    }
    const listed: VariableSelection = { variables: names, exclude: [] };
    return listed;
  });
}

const TOKEN_REF = closedRecord(
  ' must be an object of the form { "environment": "<environment ID>", "name": "<variable name>" }',
  ["environment", "name"],
  "accepted: environment, name",
).pipe(
  Schema.decodeTo(
    Schema.Struct({
      environment: environmentId(
        " must be the maruhi environment ID that holds the token",
      ).annotateKey({
        messageMissingKey: " must be the maruhi environment ID that holds the token",
      }),
      name: nonEmpty(" must be the name of the variable that holds the token").annotateKey({
        messageMissingKey: " must be the name of the variable that holds the token",
      }),
    }),
  ),
);

const WORKFLOW = closedRecord(
  ' must be an object of the form { "file": "<workflow file name>" }',
  ["file", "ref", "command"],
  "accepted: file, ref, command",
).pipe(
  Schema.decodeTo(
    Schema.Struct({
      file: ghArgument(
        " must be the workflow's file name (for example maruhi-sync.yml)",
      ).annotateKey({
        messageMissingKey: " must be the workflow's file name (for example maruhi-sync.yml)",
      }),
      ref: Schema.optionalKey(ghArgument(" must be a branch or tag name")),
      command: Schema.optionalKey(nonEmpty(" must be a non-empty path to the installed gh CLI")),
    }),
  ),
);

const RECEIPTS = closedRecord(
  ' must be an object of the form { "environment": "<environment ID>" }',
  ["environment"],
  "accepted: environment",
).pipe(
  Schema.decodeTo(
    Schema.Struct({
      environment: environmentId(
        " must be a maruhi environment ID (create it with `maruhi env create`)",
      ).annotateKey({
        messageMissingKey: " must be a maruhi environment ID (create it with `maruhi env create`)",
      }),
    }),
  ),
);

const CWD_MESSAGE = " must be a non-empty relative path";
const CWD = undefinedOr(CWD_MESSAGE, nonEmpty(CWD_MESSAGE));

function parseExecDriver(
  record: Record<string, unknown>,
  spec: ExecPreset,
  configDir: string,
): Parsed<TargetDriver> {
  return Result.gen(function* () {
    if (record["token"] !== undefined) {
      return yield* refuse(
        " applies only to the http driver (the exec driver uses the vendor CLI's own sign-in)",
        ["token"],
      );
    }
    const cwd = yield* field(record, "cwd", CWD);
    const commandMessage = ` must be a non-empty path to the installed ${spec.command} CLI`;
    const command = yield* field(
      record,
      "command",
      undefinedOr(commandMessage, nonEmpty(commandMessage)),
    );
    const driver: TargetDriver = {
      kind: "exec",
      spec,
      cwd: cwd === undefined ? configDir : join(configDir, cwd),
      command: command ?? spec.command,
      namedCommand: command !== undefined,
    };
    return driver;
  });
}

function parseHttpDriver(record: Record<string, unknown>, spec: HttpPreset): Parsed<TargetDriver> {
  return Result.gen(function* () {
    for (const key of ["cwd", "command"] as const) {
      if (record[key] !== undefined) {
        return yield* refuse(
          " applies only to the exec driver (the http driver runs no vendor CLI)",
          [key],
        );
      }
    }
    if (record["token"] === undefined) {
      return yield* refuse(
        ` is required for the http driver: { "environment": "<environment ID>", "name": "<variable name>" } naming the maruhi variable that holds ${spec.tokenHint}`,
        ["token"],
      );
    }
    const token = yield* field(record, "token", TOKEN_REF);
    const driver: TargetDriver = { kind: "http", spec, token };
    return driver;
  });
}

const DRIVER_MESSAGE =
  ' must be "exec" (the installed vendor CLI; the default when the preset has one) or "http" (the vendor API with a token stored in maruhi)';
const DRIVER = nullishOr(
  DRIVER_MESSAGE,
  Schema.Literals(["exec", "http"]).annotate({ message: DRIVER_MESSAGE }),
);

function parseDriverKind(record: Record<string, unknown>, preset: SyncPreset): Parsed<DriverKind> {
  return Result.gen(function* () {
    const kind = (yield* field(record, "driver", DRIVER)) ?? defaultDriverOf(preset);
    const declaration = kind === "exec" ? preset.exec : preset.http;
    if (isUnavailable(declaration)) {
      return yield* refuse(`: ${declaration.unavailable}; use "${defaultDriverOf(preset)}"`, [
        "driver",
      ]);
    }
    return kind;
  });
}

const TARGET_RECORD = objectLeaf(" must be an object");
const PRESET = Schema.Literals(PRESET_IDS).annotate({
  message: ` must be one of ${PRESET_IDS.join(", ")}`,
});
const TARGET_ENVIRONMENT = environmentId(" must be a maruhi environment ID");

interface TargetHead {
  readonly record: Record<string, unknown>;
  readonly preset: SyncPreset;
  readonly driverKind: DriverKind;
  readonly environment: EnvironmentId;
}

function parseTargetHead(name: string, value: unknown): Parsed<TargetHead> {
  return Result.gen(function* () {
    if (!TARGET_NAME.test(name)) {
      return yield* refuse(
        "target names must start with an alphanumeric character, followed by up to 63 alphanumerics, _ or - (key under targets)",
      );
    }
    const record = yield* decode(TARGET_RECORD, value);
    yield* knownKeys(record, TARGET_KEYS, `accepted: ${TARGET_KEYS.join(", ")}`);
    const preset = SYNC_PRESETS[yield* field(record, "preset", PRESET)];
    const driverKind = yield* parseDriverKind(record, preset);
    const environment = yield* field(record, "environment", TARGET_ENVIRONMENT);
    const head: TargetHead = { record, preset, driverKind, environment };
    return head;
  });
}

function parseDriver(
  record: Record<string, unknown>,
  preset: SyncPreset,
  driverKind: DriverKind,
  configDir: string,
): Parsed<TargetDriver> {
  if (driverKind === "exec") {
    return isUnavailable(preset.exec)
      ? refuse(preset.exec.unavailable)
      : parseExecDriver(record, preset.exec, configDir);
  }
  return isUnavailable(preset.http)
    ? refuse(preset.http.unavailable)
    : parseHttpDriver(record, preset.http);
}

function parseDriverAndOptions(
  record: Record<string, unknown>,
  preset: SyncPreset,
  driverKind: DriverKind,
  configDir: string,
): Parsed<{ readonly driver: TargetDriver; readonly options: ResolvedOptions }> {
  return Result.gen(function* () {
    const driver = yield* parseDriver(record, preset, driverKind, configDir);
    const given = (yield* field(record, "options", OPTIONS)) ?? {};
    const options = yield* parseTargetOptions(preset.id, driverKind, driver.spec.options, given);
    const inconsistent = driver.spec.check?.(options) ?? null;
    if (inconsistent !== null) {
      return yield* refuse(`.${inconsistent}`, ["options"]);
    }
    return { driver, options };
  });
}

function excludeToken(
  name: string,
  selection: VariableSelection,
  driver: TargetDriver,
  environment: string,
): Parsed<readonly string[]> {
  if (driver.kind !== "http" || driver.token.environment !== environment) {
    return Result.succeed(selection.exclude);
  }
  if (selection.variables !== "all") {
    return selection.variables.includes(driver.token.name)
      ? refuse(
          ` lists the token variable (targets.${name}.token.name); the integration token is never copied to the target`,
          ["variables"],
        )
      : Result.succeed(selection.exclude);
  }
  return Result.succeed(
    selection.exclude.includes(driver.token.name)
      ? selection.exclude
      : [...selection.exclude, driver.token.name],
  );
}

const ON_PUSH = Schema.Literals(["apply", "workflow"]).annotate({
  message:
    ' must be "apply" (sync from this machine right after `maruhi push`) or "workflow" (trigger the repository\'s workflow with gh so CI syncs); leave it out to sync only by hand',
});

const WORKFLOW_ONLY = ' applies only when onPush is "workflow"';

function parseOnPush(
  record: Record<string, unknown>,
  isProduction: boolean,
  configDir: string,
): Parsed<OnPush | null> {
  return Result.gen(function* () {
    if (record["onPush"] === undefined) {
      return record["workflow"] === undefined ? null : yield* refuse(WORKFLOW_ONLY, ["workflow"]);
    }
    const onPush = yield* field(record, "onPush", ON_PUSH);
    if (onPush === "workflow") {
      return yield* parseWorkflow(record, configDir);
    }
    if (record["workflow"] !== undefined) {
      return yield* refuse(WORKFLOW_ONLY, ["workflow"]);
    }
    if (isProduction) {
      return yield* refuse(
        ' cannot be "apply" for a production target: production is written only by an explicit `maruhi sync apply --yes`. Use "workflow" to let CI write it under the --yes in the workflow file, or set production to false if the target is not production',
        ["onPush"],
      );
    }
    const apply: OnPush = { kind: "apply" };
    return apply;
  });
}

function parseWorkflow(record: Record<string, unknown>, configDir: string): Parsed<OnPush> {
  return Result.gen(function* () {
    if (record["workflow"] === undefined) {
      return yield* refuse(
        ' is required when onPush is "workflow": { "file": "<workflow file name>" } naming the workflow that runs `maruhi ci sync` (it must have a workflow_dispatch trigger with a "target" input)',
        ["workflow"],
      );
    }
    const workflow = yield* field(record, "workflow", WORKFLOW);
    const onPush: OnPush = {
      kind: "workflow",
      file: workflow.file,
      ref: workflow.ref,
      command: workflow.command ?? "gh",
      namedCommand: workflow.command !== undefined,
      cwd: configDir,
    };
    return onPush;
  });
}

const PRODUCTION_MESSAGE = " must be true or false";
const PRODUCTION = undefinedOr(
  PRODUCTION_MESSAGE,
  Schema.Boolean.annotate({ message: PRODUCTION_MESSAGE }),
);

function parseTarget(name: string, value: unknown, configDir: string): Parsed<SyncTarget> {
  return Result.gen(function* () {
    const { record, preset, driverKind, environment } = yield* parseTargetHead(name, value);
    const selection = yield* parseVariables(record);
    const production = yield* field(record, "production", PRODUCTION);
    const { driver, options } = yield* parseDriverAndOptions(record, preset, driverKind, configDir);
    const exclude = yield* excludeToken(name, selection, driver, environment);
    const isProduction = production ?? preset.isProduction(options);
    const onPush = yield* parseOnPush(record, isProduction, configDir);
    const target: SyncTarget = {
      name,
      preset,
      driver,
      environment,
      variables: selection.variables,
      exclude,
      production: isProduction,
      options,
      onPush,
    };
    return target;
  });
}

const ROOT_KEYS = ["version", "project", "receipts", "targets"] as const;

const TARGETS_MESSAGE = " must be an object with at least one target";
const TARGETS = objectLeaf(TARGETS_MESSAGE);

function parseTargets(
  record: Record<string, unknown>,
  root: {
    readonly configDir: string;
    readonly receiptsEnvironment: EnvironmentId;
    readonly projectId: ProjectId | undefined;
  },
): Parsed<ReadonlyMap<string, SyncTarget>> {
  return Result.gen(function* () {
    const raw = yield* field(record, "targets", TARGETS);
    if (Object.keys(raw).length === 0) {
      return yield* refuse(TARGETS_MESSAGE, ["targets"]);
    }
    const targets = new Map<string, SyncTarget>();
    for (const [name, value] of Object.entries(raw)) {
      const target = yield* at(["targets", name], parseTarget(name, value, root.configDir));
      if (target.environment === root.receiptsEnvironment) {
        return yield* refuse(
          ` is the receipts environment (${root.receiptsEnvironment}); receipts must live in an environment that is not synced`,
          ["targets", name, "environment"],
        );
      }
      if (target.onPush !== null && root.projectId === undefined) {
        return yield* refuse(
          ' needs the top-level "project": sync on push only uses a config that names its project (add it, or generate the config with `maruhi sync init --project <project ID>`)',
          ["targets", name, "onPush"],
        );
      }
      targets.set(name, target);
    }
    return targets;
  });
}

function parseSyncDocument(record: Record<string, unknown>, configDir: string): Parsed<SyncConfig> {
  return Result.gen(function* () {
    const { projectId } = yield* configHeader(record, ROOT_KEYS);
    const receipts = yield* field(record, "receipts", RECEIPTS);
    const receiptsEnvironment = receipts.environment;
    const targets = yield* parseTargets(record, { configDir, receiptsEnvironment, projectId });
    const config: SyncConfig = { version: 1, projectId, receiptsEnvironment, targets };
    return config;
  });
}

export function parseSyncConfig(content: string, configDir: string): SyncConfig | Invalid {
  return parseConfigDocument(content, (record) => parseSyncDocument(record, configDir));
}

export function loadSyncConfig(path: string): Effect.Effect<SyncConfig, CliError> {
  return loadConfig(
    path,
    "sync config",
    "Create it with `maruhi sync init` (see the Deploy targets page in the docs), or pass --config <file>",
    (content) => parseSyncConfig(content, dirname(path)),
  ).pipe(Effect.map(({ parsed }) => parsed));
}

export function loadSyncConfigIfPresent(path: string): Effect.Effect<SyncConfig | null, CliError> {
  return loadIfPresent(
    path,
    loadSyncConfig,
    `Cannot read the sync config ${path} (it exists but is not readable). Fix it, or pass --no-sync to push without syncing`,
  );
}

export function requireSyncTarget(
  config: SyncConfig,
  name: string,
): Effect.Effect<SyncTarget, CliError> {
  const target = config.targets.get(name);
  if (target === undefined) {
    return Effect.fail(
      usageError(
        `Unknown sync target (targets in the config: ${[...config.targets.keys()].join(", ")})`,
      ),
    );
  }
  return Effect.succeed(target);
}

export function checkConfigProject(
  config: SyncConfig,
  projectFlag: string | undefined,
): Effect.Effect<void, CliError> {
  if (
    config.projectId !== undefined &&
    projectFlag !== undefined &&
    projectFlag !== config.projectId
  ) {
    return Effect.fail(
      usageError(
        "--project does not match the `project` in the sync config (the config belongs to a different project)",
      ),
    );
  }
  return Effect.void;
}
