// The repository sync config of `maruhi sync` (stage 1 —
// integration-options.md §3 supplement 15 X1 "the sync's correspondence
// config lives in the repository (non-secret)". Stage 2 added `driver` /
// `token`).
//
// The "maruhi environment → sync destination (preset) / destination's
// environment / variables carried" correspondence is not a secret — it
// is a config versioned together with the code. The same treatment as
// the repository anchor (anchor.ts — the user commits the JSON of
// `maruhi project anchor`), within the "non-secret configuration" the
// CLI may persist (CLAUDE.md). No integration token is held: the exec
// driver uses the vendor CLI's own sign-in (supplement 16), and the http
// driver only **points at** a normal maruhi variable (an environment ID
// and a variable name — supplement 15 X2). The receipts' location (an
// environment ID) is also pointed at here (X3 (a)).
//
// The format: a single JSON file (default `maruhi.sync.json`,
// overridable with `--config`). Has a version field, and unknown keys
// are refused (a typo is never silently ignored). `version: 1` stays
// stage-1-shaped (every stage-2 key is optional and a stage-1 config
// still reads as-is. A stage-1 CLI refuses stage-2 keys as "unknown
// keys" — compatibility runs backward only. Ruling H). Stage 3's
// `onPush` / `workflow` get the same treatment (omitted = manual sync
// only). The validation's wording says "which key and why" and never
// shows the value that was typed.

import { readFile, stat } from "node:fs/promises";
import { dirname, join } from "node:path";

import { isEnvironmentId, isProjectId } from "@maruhi/core";
import { Effect } from "effect";

import { cliError, type CliError, usageError } from "./errors.ts";
import { parseJsonRecord } from "./json-record.ts";
import type { ExecPreset } from "./sync-exec.ts";
import type { HttpPreset } from "./sync-http.ts";
import { defaultDriverOf, isUnavailable, type SyncPreset, SYNC_PRESETS } from "./sync-preset.ts";
import type { DriverKind, OptionSpec, PresetId, ResolvedOptions } from "./sync-types.ts";

/** Default location of the sync config, relative to the working directory. */
export const DEFAULT_SYNC_CONFIG_PATH = "maruhi.sync.json";

/** Where the integration token lives: a normal variable of some environment. */
export interface TokenRef {
  readonly environment: string;
  readonly name: string;
}

/** How one target is driven: the installed vendor CLI, or the vendor API. */
export type TargetDriver =
  | {
      readonly kind: "exec";
      readonly spec: ExecPreset;
      /** The vendor CLI's working directory (the relative path from the config file's location, resolved). */
      readonly cwd: string;
      /** The executable to launch (default: the preset's command name = the installed CLI on PATH). */
      readonly command: string;
      /** The config wrote `command` (= the config named the executable — true even if it spells the default). */
      readonly namedCommand: boolean;
    }
  | {
      readonly kind: "http";
      readonly spec: HttpPreset;
      readonly token: TokenRef;
    };

/**
 * What `maruhi push` does for the target right after a push lands in its
 * source environment (stage 3 — integration-options.md §3 supplement 4
 * N1 / supplement 7 P1): apply directly from the writer's CLI, or trigger the repository's
 * workflow with `gh workflow run` so CI applies it (`maruhi ci sync`). The
 * writer then never holds the target's token. `null` = only by hand.
 */
export type OnPush =
  | { readonly kind: "apply" }
  | {
      readonly kind: "workflow";
      /** The workflow file name (or name / ID) passed to `gh workflow run`. */
      readonly file: string;
      /** `--ref` for the dispatch (undefined = gh's default: the repository's default branch). */
      readonly ref: string | undefined;
      /** The `gh` executable (default: `gh` on PATH). */
      readonly command: string;
      /** The config wrote `workflow.command` (it names the program to run, even if it spells the default). */
      readonly namedCommand: boolean;
      /** Where `gh` runs (the config file's directory; gh resolves the repository from its git remote). */
      readonly cwd: string;
    };

/** One deploy target: which maruhi environment goes where, and how. */
export interface SyncTarget {
  /** The target's name (the config's key — becomes part of the receipt variable name). */
  readonly name: string;
  readonly preset: SyncPreset;
  readonly driver: TargetDriver;
  /** The maruhi environment ID to decrypt. */
  readonly environment: string;
  /** An explicit list of variable names to carry, or every active variable of the environment (`"all"`). */
  readonly variables: readonly string[] | "all";
  /**
   * Names excluded from `"all"` (public config / platform-owned
   * resources — supplement 13 W3). When the integration token lives in
   * the same environment as the sync source, its name lands here even
   * without the config listing it (never carries the token — guaranteed
   * by structure).
   */
  readonly exclude: readonly string[];
  /** Treated as production (apply requires `--yes` — supplement 14 M4). */
  readonly production: boolean;
  /** The preset-specific options (verified against the chosen driver's declaration). */
  readonly options: ResolvedOptions;
  /** The automatic sync right after a push (omitted = manual only). */
  readonly onPush: OnPush | null;
}

/** The parsed repository sync config. */
export interface SyncConfig {
  readonly version: 1;
  /** The project the config belongs to (optional. When given, checked against the resolved project). */
  readonly projectId: string | undefined;
  /** The environment ID where receipt variables live (supplement 15 X3 (a)). */
  readonly receiptsEnvironment: string;
  readonly targets: ReadonlyMap<string, SyncTarget>;
}

// A target name is limited to the same character class as an environment
// ID (it becomes part of the receipt variable name `sync-receipt:<name>`
// — kept in a shape that needs no neutralizing for display or matching)
const TARGET_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

/** A validation failure (the reason's string). Never includes the value itself. */
type Invalid = string;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function unknownKeys(record: Record<string, unknown>, allowed: readonly string[]): string[] {
  return Object.keys(record).filter((key) => !allowed.includes(key));
}

function nonEmptyStringList(value: unknown): readonly string[] | null {
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === "string")) {
    return null;
  }
  const list = value as string[];
  return list.every((entry) => entry.trim().length > 0) ? list : null;
}

/** Validating one option's value (follows the declared spec. The reason when invalid). */
function parseOptionValue(
  spec: OptionSpec,
  given: unknown,
  path: string,
): { readonly value: string | boolean } | Invalid {
  if (spec.type === "boolean") {
    return typeof given === "boolean" ? { value: given } : `${path} must be true or false`;
  }
  if (typeof given !== "string" || given.trim().length === 0) {
    return `${path} must be a non-empty string`;
  }
  if (spec.values !== undefined && !spec.values.includes(given)) {
    return `${path} must be one of ${spec.values.join(", ")}`;
  }
  if (spec.pattern !== undefined && !spec.pattern.regex.test(given)) {
    return `${path} must be ${spec.pattern.hint}`;
  }
  return { value: given };
}

/** Validating the preset-specific options (follows the chosen driver's declaration — data-driven). */
function parseTargetOptions(
  presetId: PresetId,
  driverKind: DriverKind,
  declaredOptions: Readonly<Record<string, OptionSpec>>,
  value: unknown,
  path: string,
): ResolvedOptions | Invalid {
  const record = value === undefined ? {} : value;
  if (!isRecord(record)) {
    return `${path} must be an object`;
  }
  const declared = Object.keys(declaredOptions);
  const unknown = unknownKeys(record, declared);
  if (unknown.length > 0) {
    return `${path} has unknown keys (${unknown.join(", ")}); the ${presetId} preset with the ${driverKind} driver accepts: ${declared.join(", ")}`;
  }
  const options: Record<string, string | boolean> = {};
  for (const [key, spec] of Object.entries(declaredOptions)) {
    const given = record[key];
    if (given === undefined) {
      if (spec.required) {
        return `${path}.${key} is required for the ${presetId} preset with the ${driverKind} driver${spec.values === undefined ? "" : ` (one of ${spec.values.join(", ")})`}`;
      }
      continue;
    }
    const parsedValue = parseOptionValue(spec, given, `${path}.${key}`);
    if (typeof parsedValue === "string") {
      return parsedValue;
    }
    options[key] = parsedValue.value;
  }
  return options;
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

function parseVariables(
  record: Record<string, unknown>,
  path: string,
): { variables: readonly string[] | "all"; exclude: readonly string[] } | Invalid {
  const raw = record["variables"];
  const exclude = record["exclude"];
  if (raw === "all") {
    const parsed = exclude === undefined ? [] : nonEmptyStringList(exclude);
    if (parsed === null) {
      return `${path}.exclude must be an array of variable names`;
    }
    return { variables: "all", exclude: parsed };
  }
  const list = nonEmptyStringList(raw);
  if (list === null || list.length === 0) {
    return `${path}.variables must be a non-empty array of variable names, or "all"`;
  }
  if (exclude !== undefined) {
    return `${path}.exclude applies only when variables is "all"`;
  }
  if (new Set(list).size !== list.length) {
    return `${path}.variables lists the same name more than once`;
  }
  return { variables: list, exclude: [] };
}

/** An optional non-empty-string key (undefined when absent, the reason when malformed). */
function optionalString(
  record: Record<string, unknown>,
  key: string,
  path: string,
  expected: string,
): { readonly value: string | undefined } | Invalid {
  const given = record[key];
  if (given === undefined) {
    return { value: undefined };
  }
  if (typeof given !== "string" || given.trim().length === 0) {
    return `${path}.${key} must be ${expected}`;
  }
  return { value: given };
}

/** Interpreting `token: { environment, name }` (where the http driver's integration token lives). */
function parseTokenRef(value: unknown, path: string): TokenRef | Invalid {
  if (!isRecord(value)) {
    return `${path} must be an object of the form { "environment": "<environment ID>", "name": "<variable name>" }`;
  }
  const unknown = unknownKeys(value, ["environment", "name"]);
  if (unknown.length > 0) {
    return `${path} has unknown keys (${unknown.join(", ")}); accepted: environment, name`;
  }
  const environment = value["environment"];
  if (typeof environment !== "string" || !isEnvironmentId(environment)) {
    return `${path}.environment must be the maruhi environment ID that holds the token`;
  }
  const name = value["name"];
  if (typeof name !== "string" || name.trim().length === 0) {
    return `${path}.name must be the name of the variable that holds the token`;
  }
  return { environment, name };
}

/** Interpreting the exec driver's run surface (cwd / command). */
function parseExecDriver(
  record: Record<string, unknown>,
  path: string,
  spec: ExecPreset,
  configDir: string,
): TargetDriver | Invalid {
  if (record["token"] !== undefined) {
    return `${path}.token applies only to the http driver (the exec driver uses the vendor CLI's own sign-in)`;
  }
  const cwd = optionalString(record, "cwd", path, "a non-empty relative path");
  if (typeof cwd === "string") {
    return cwd;
  }
  const command = optionalString(
    record,
    "command",
    path,
    `a non-empty path to the installed ${spec.command} CLI`,
  );
  if (typeof command === "string") {
    return command;
  }
  return {
    kind: "exec",
    spec,
    cwd: cwd.value === undefined ? configDir : join(configDir, cwd.value),
    command: command.value ?? spec.command,
    namedCommand: command.value !== undefined,
  };
}

/** Interpreting the http driver's credential surface (token). */
function parseHttpDriver(
  record: Record<string, unknown>,
  path: string,
  spec: HttpPreset,
): TargetDriver | Invalid {
  for (const key of ["cwd", "command"] as const) {
    if (record[key] !== undefined) {
      return `${path}.${key} applies only to the exec driver (the http driver runs no vendor CLI)`;
    }
  }
  if (record["token"] === undefined) {
    return `${path}.token is required for the http driver: { "environment": "<environment ID>", "name": "<variable name>" } naming the maruhi variable that holds ${spec.tokenHint}`;
  }
  const token = parseTokenRef(record["token"], `${path}.token`);
  if (typeof token === "string") {
    return token;
  }
  return { kind: "http", spec, token };
}

/** Interpreting the target's shape (key, preset, driver, environment). */
function parseTargetHead(
  name: string,
  value: unknown,
):
  | {
      record: Record<string, unknown>;
      preset: SyncPreset;
      driverKind: DriverKind;
      environment: string;
    }
  | Invalid {
  const path = `targets.${name}`;
  if (!TARGET_NAME.test(name)) {
    return `target names must start with an alphanumeric character, followed by up to 63 alphanumerics, _ or - (key under targets)`;
  }
  if (!isRecord(value)) {
    return `${path} must be an object`;
  }
  const unknown = unknownKeys(value, TARGET_KEYS);
  if (unknown.length > 0) {
    return `${path} has unknown keys (${unknown.join(", ")}); accepted: ${TARGET_KEYS.join(", ")}`;
  }
  const preset = presetOf(value["preset"]);
  if (preset === undefined) {
    return `${path}.preset must be one of ${Object.keys(SYNC_PRESETS).join(", ")}`;
  }
  const driverKind = driverKindOf(value["driver"], preset, path);
  if (typeof driverKind === "string") {
    return driverKind;
  }
  const environment = value["environment"];
  if (typeof environment !== "string" || !isEnvironmentId(environment)) {
    return `${path}.environment must be a maruhi environment ID`;
  }
  return { record: value, preset, driverKind: driverKind.kind, environment };
}

/** Resolving the preset id (own-property lookup — never resolves `__proto__` etc.). */
function presetOf(value: unknown): SyncPreset | undefined {
  return typeof value === "string" && Object.hasOwn(SYNC_PRESETS, value)
    ? SYNC_PRESETS[value as PresetId]
    : undefined;
}

/**
 * Resolving `driver` (omitted = the preset's default: exec when it has
 * one, else http). A config naming a driver the preset does not have is
 * refused with the reason (the declaration's `unavailable`) attached.
 */
function driverKindOf(
  value: unknown,
  preset: SyncPreset,
  path: string,
): { readonly kind: DriverKind } | Invalid {
  const driver = value ?? defaultDriverOf(preset);
  if (driver !== "exec" && driver !== "http") {
    return `${path}.driver must be "exec" (the installed vendor CLI; the default when the preset has one) or "http" (the vendor API with a token stored in maruhi)`;
  }
  const declaration = driver === "exec" ? preset.exec : preset.http;
  return isUnavailable(declaration)
    ? `${path}.driver: ${declaration.unavailable}; use "${defaultDriverOf(preset)}"`
    : { kind: driver };
}

function parseTarget(name: string, value: unknown, configDir: string): SyncTarget | Invalid {
  const path = `targets.${name}`;
  const head = parseTargetHead(name, value);
  if (typeof head === "string") {
    return head;
  }
  const { record, preset, driverKind, environment } = head;
  const selection = parseVariables(record, path);
  if (typeof selection === "string") {
    return selection;
  }
  const production = record["production"];
  if (production !== undefined && typeof production !== "boolean") {
    return `${path}.production must be true or false`;
  }
  const driven = parseDriverAndOptions(record, path, preset, driverKind, configDir);
  if (typeof driven === "string") {
    return driven;
  }
  const { driver, options } = driven;
  const exclude = excludeToken(selection, driver, environment, path);
  if (typeof exclude === "string") {
    return exclude;
  }
  // Absent an explicit value, the preset decides (Vercel = production
  // environment, Workers = no named environment). Since it is a
  // misoperation guard, the default falls toward "production"
  const isProduction = production ?? preset.isProduction(options);
  const onPush = parseOnPush(record, path, isProduction, configDir);
  if (typeof onPush === "string") {
    return onPush;
  }
  return {
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
}

/**
 * Interpreting `onPush` / `workflow` (stage 3 — rulings B / C). `"apply"`
 * is the shape where the writer's CLI applies directly, and is refused
 * **at config time** for a production target (production is written only
 * by a person typing `--yes` on `maruhi sync apply` — stage 1's ruling
 * J). `"workflow"` is the shape that launches CI with `gh workflow run`;
 * the value is written by the CI workflow (where the `--yes` is
 * visible), so it is allowed even for production.
 */
function parseOnPush(
  record: Record<string, unknown>,
  path: string,
  isProduction: boolean,
  configDir: string,
): OnPush | null | Invalid {
  const onPush = record["onPush"];
  const workflow = record["workflow"];
  if (onPush === undefined) {
    return workflow === undefined
      ? null
      : `${path}.workflow applies only when onPush is "workflow"`;
  }
  if (onPush !== "apply" && onPush !== "workflow") {
    return `${path}.onPush must be "apply" (sync from this machine right after \`maruhi push\`) or "workflow" (trigger the repository's workflow with gh so CI syncs); leave it out to sync only by hand`;
  }
  if (onPush === "apply") {
    if (workflow !== undefined) {
      return `${path}.workflow applies only when onPush is "workflow"`;
    }
    if (isProduction) {
      return `${path}.onPush cannot be "apply" for a production target: production is written only by an explicit \`maruhi sync apply --yes\`. Use "workflow" to let CI write it under the --yes in the workflow file, or set production to false if the target is not production`;
    }
    return { kind: "apply" };
  }
  return parseWorkflow(workflow, `${path}.workflow`, configDir);
}

/** Interpreting `workflow: { file, ref?, command? }` (required when onPush is "workflow"). */
function parseWorkflow(value: unknown, path: string, configDir: string): OnPush | Invalid {
  const record = workflowRecord(value, path);
  if (typeof record === "string") {
    return record;
  }
  const file = ghArgument(record["file"]);
  if (file === undefined) {
    return `${path}.file must be the workflow's file name (for example maruhi-sync.yml)`;
  }
  const ref = record["ref"] === undefined ? undefined : ghArgument(record["ref"]);
  if (record["ref"] !== undefined && ref === undefined) {
    return `${path}.ref must be a branch or tag name`;
  }
  const command = optionalString(
    record,
    "command",
    path,
    "a non-empty path to the installed gh CLI",
  );
  if (typeof command === "string") {
    return command;
  }
  return {
    kind: "workflow",
    file,
    ref,
    command: command.value ?? "gh",
    namedCommand: command.value !== undefined,
    cwd: configDir,
  };
}

/** The `workflow` shape (presence, object, known keys). */
function workflowRecord(value: unknown, path: string): Record<string, unknown> | Invalid {
  if (value === undefined) {
    return `${path} is required when onPush is "workflow": { "file": "<workflow file name>" } naming the workflow that runs \`maruhi ci sync\` (it must have a workflow_dispatch trigger with a "target" input)`;
  }
  if (!isRecord(value)) {
    return `${path} must be an object of the form { "file": "<workflow file name>" }`;
  }
  const unknown = unknownKeys(value, ["file", "ref", "command"]);
  return unknown.length > 0
    ? `${path} has unknown keys (${unknown.join(", ")}); accepted: file, ref, command`
    : value;
}

/**
 * A config value that lands on gh's argv (the workflow name, ref):
 * non-empty and not starting with `-` (never let a config build a shape
 * read as a flag).
 */
function ghArgument(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 && !value.startsWith("-")
    ? value
    : undefined;
}

/** The driver's surface (exec = cwd / command, http = token) and the options verified against that driver's declaration. */
function parseDriverAndOptions(
  record: Record<string, unknown>,
  path: string,
  preset: SyncPreset,
  driverKind: DriverKind,
  configDir: string,
): { readonly driver: TargetDriver; readonly options: ResolvedOptions } | Invalid {
  const driver = parseDriver(record, path, preset, driverKind, configDir);
  if (typeof driver === "string") {
    return driver;
  }
  const options = parseTargetOptions(
    preset.id,
    driverKind,
    driver.spec.options,
    record["options"],
    `${path}.options`,
  );
  if (typeof options === "string") {
    return options;
  }
  // The options' mutual consistency (the preset's `check` — Netlify's
  // context / branch / secret, GitHub's environment / app)
  const inconsistent = driver.spec.check?.(options) ?? null;
  return inconsistent === null ? { driver, options } : `${path}.options.${inconsistent}`;
}

/** Reads the target's driver surface against the chosen driver's declaration (parseTargetHead already refused a missing declaration). */
function parseDriver(
  record: Record<string, unknown>,
  path: string,
  preset: SyncPreset,
  driverKind: DriverKind,
  configDir: string,
): TargetDriver | Invalid {
  if (driverKind === "exec") {
    return isUnavailable(preset.exec)
      ? preset.exec.unavailable
      : parseExecDriver(record, path, preset.exec, configDir);
  }
  return isUnavailable(preset.http)
    ? preset.http.unavailable
    : parseHttpDriver(record, path, preset.http);
}

/**
 * The token lives in the same environment as the sync source: an error
 * if it appears on the explicit list; under "all" it is silently
 * excluded (the structure guarantees the token is never carried to the
 * target).
 */
function excludeToken(
  selection: { readonly variables: readonly string[] | "all"; readonly exclude: readonly string[] },
  driver: TargetDriver,
  environment: string,
  path: string,
): readonly string[] | Invalid {
  if (driver.kind !== "http" || driver.token.environment !== environment) {
    return selection.exclude;
  }
  if (selection.variables !== "all") {
    return selection.variables.includes(driver.token.name)
      ? `${path}.variables lists the token variable (${path}.token.name); the integration token is never copied to the target`
      : selection.exclude;
  }
  return selection.exclude.includes(driver.token.name)
    ? selection.exclude
    : [...selection.exclude, driver.token.name];
}

const ROOT_KEYS = ["version", "project", "receipts", "targets"] as const;

function parseReceipts(value: unknown): { readonly environment: string } | Invalid {
  if (!isRecord(value)) {
    return 'receipts must be an object of the form { "environment": "<environment ID>" }';
  }
  const unknown = unknownKeys(value, ["environment"]);
  if (unknown.length > 0) {
    return `receipts has unknown keys (${unknown.join(", ")}); accepted: environment`;
  }
  const environment = value["environment"];
  if (typeof environment !== "string" || !isEnvironmentId(environment)) {
    return "receipts.environment must be a maruhi environment ID (create it with `maruhi env create`)";
  }
  return { environment };
}

/** Interpreting the config JSON (the reason's string when invalid). */
export function parseSyncConfig(content: string, configDir: string): SyncConfig | Invalid {
  const parsed = parseJsonRecord(content);
  if (typeof parsed === "string") {
    return parsed;
  }
  const unknown = unknownKeys(parsed, ROOT_KEYS);
  if (unknown.length > 0) {
    return `unknown top-level keys (${unknown.join(", ")}); accepted: ${ROOT_KEYS.join(", ")}`;
  }
  if (parsed["version"] !== 1) {
    return "unsupported config version (expected 1)";
  }
  const project = parsed["project"];
  if (project !== undefined && (typeof project !== "string" || !isProjectId(project))) {
    return "project must be the project ID (64 hex digits) when present";
  }
  const receipts = parseReceipts(parsed["receipts"]);
  if (typeof receipts === "string") {
    return receipts;
  }
  const receiptsEnvironment = receipts.environment;
  const targetsRaw = parsed["targets"];
  if (!isRecord(targetsRaw) || Object.keys(targetsRaw).length === 0) {
    return "targets must be an object with at least one target";
  }
  const targets = parseTargets(targetsRaw, { configDir, receiptsEnvironment, project });
  return typeof targets === "string"
    ? targets
    : { version: 1, projectId: project, receiptsEnvironment, targets };
}

/** Interpreting each target of `targets` and the checks spanning the whole config (the receipts environment, `project`). */
function parseTargets(
  targetsRaw: Record<string, unknown>,
  root: {
    readonly configDir: string;
    readonly receiptsEnvironment: string;
    readonly project: string | undefined;
  },
): ReadonlyMap<string, SyncTarget> | Invalid {
  const targets = new Map<string, SyncTarget>();
  for (const [name, value] of Object.entries(targetsRaw)) {
    const target = parseTarget(name, value, root.configDir);
    if (typeof target === "string") {
      return target;
    }
    // Never make the receipts environment a sync source: blocks both the
    // shape where `maruhi run --env <receipts>` injects even receipt
    // variables into the child, and the shape that carries a receipt
    // itself to the target
    if (target.environment === root.receiptsEnvironment) {
      return `targets.${name}.environment is the receipts environment (${root.receiptsEnvironment}); receipts must live in an environment that is not synced`;
    }
    // The post-push sync is only used with a config that names which
    // project it belongs to (stage 3's ruling B — never silently apply
    // cwd's config to a different project's push)
    if (target.onPush !== null && root.project === undefined) {
      return `targets.${name}.onPush needs the top-level "project": sync on push only uses a config that names its project (add it, or generate the config with \`maruhi sync init --project <project ID>\`)`;
    }
    targets.set(name, target);
  }
  return targets;
}

/** Loading and verifying `--config <file>` (default `maruhi.sync.json`). */
export function loadSyncConfig(path: string): Effect.Effect<SyncConfig, CliError> {
  return Effect.gen(function* () {
    const content = yield* Effect.tryPromise({
      try: () => readFile(path, "utf8"),
      catch: () =>
        cliError(
          `Cannot read the sync config ${path}. Create it with \`maruhi sync init\` (see the Deploy targets page in the docs), or pass --config <file>`,
        ),
    });
    const parsed = parseSyncConfig(content, dirname(path));
    if (typeof parsed === "string") {
      return yield* Effect.fail(cliError(`The sync config ${path} is invalid: ${parsed}`));
    }
    return parsed;
  });
}

/**
 * The default config when it exists in the working directory (`maruhi push`
 * looks for it without being told): null when the file is absent, and the
 * same errors as {@link loadSyncConfig} when it exists but cannot be read or
 * is invalid — a broken config is reported, not skipped.
 */
export function loadSyncConfigIfPresent(path: string): Effect.Effect<SyncConfig | null, CliError> {
  return Effect.gen(function* () {
    const exists = yield* Effect.tryPromise({
      try: () => stat(path).then(() => true),
      catch: (error: unknown) => error,
    }).pipe(
      Effect.catch((error: unknown) =>
        (error as NodeJS.ErrnoException).code === "ENOENT"
          ? Effect.succeed(false)
          : Effect.fail(
              cliError(
                `Cannot read the sync config ${path} (it exists but is not readable). Fix it, or pass --no-sync to push without syncing`,
              ),
            ),
      ),
    );
    return exists ? yield* loadSyncConfig(path) : null;
  });
}

/** Looks a target up by name (when unknown, a usage-error-equivalent wording with the candidates attached). */
export function requireSyncTarget(
  config: SyncConfig,
  name: string,
): Effect.Effect<SyncTarget, CliError> {
  const target = config.targets.get(name);
  if (target === undefined) {
    // A word that points at nothing = a writing mistake (2). Never shows the typed name — only states the candidates
    return Effect.fail(
      usageError(
        `Unknown sync target (targets in the config: ${[...config.targets.keys()].join(", ")})`,
      ),
    );
  }
  return Effect.succeed(target);
}

/** Matching the config's `project` against the flag (a mismatch is a writing mistake = 2). */
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
