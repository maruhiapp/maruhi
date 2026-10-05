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
//
// The JSON is described with Schema and decoded with
// `Schema.decodeUnknownResult`: the leaf shapes are real schema nodes
// (String / Boolean / Literals / Record / Array / Struct), and
// everything whose wording or ordering is conditional — the driver
// dispatch, the spec-driven options, the cross-target checks — is a
// `Schema.makeFilter` in the same sequence the hand-written checks ran
// (the first reason wins, like before). The filters report
// `Schema.FilterIssue`s: a `{path, issue}` whose issue starts with a
// separator is a suffix appended to the dotted path ("targets.X.options"
// + " must be ..."), and a plain string is a complete reason; the
// wording is unchanged.

import { dirname, join } from "node:path";

import { Effect, Result, Schema } from "effect";

import {
  configHeader,
  environmentId,
  field,
  type Invalid,
  isReason,
  issueReason,
  JsonRecord,
  loadConfig,
  type Reason,
  reasonIssue,
  stringLeaf,
  unknownKeysRefusal,
} from "../config-schema.ts";
import { type CliError, usageError } from "../errors.ts";
import { loadIfPresent, parseConfigHeader } from "../json-record.ts";
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

/** A non-empty string leaf. */
const nonEmpty = (suffix: string) => stringLeaf(suffix, (value) => value.trim().length > 0);

/**
 * A config value that lands on gh's argv (the workflow file name, a ref):
 * non-empty and not starting with `-` (never let a config build a shape
 * read as a flag).
 */
const ghArgument = (suffix: string) =>
  stringLeaf(suffix, (value) => value.trim().length > 0 && !value.startsWith("-"));

/** Validating one option's value (follows the declared spec — boolean | string [+ values] [+ pattern]). */
function parseOptionValue(
  spec: OptionSpec,
  given: unknown,
): { readonly value: string | boolean } | Reason {
  if (spec.type === "boolean") {
    const decoded = Schema.decodeUnknownResult(
      Schema.Boolean.annotate({ message: " must be true or false" }),
    )(given);
    return Result.isSuccess(decoded) ? { value: decoded.success } : decoded.failure.issue;
  }
  const text = Schema.decodeUnknownResult(nonEmpty(" must be a non-empty string"))(given);
  if (Result.isFailure(text)) {
    return text.failure.issue;
  }
  if (spec.values !== undefined && !spec.values.includes(text.success)) {
    return ` must be one of ${spec.values.join(", ")}`;
  }
  if (spec.pattern !== undefined && !spec.pattern.regex.test(text.success)) {
    return ` must be ${spec.pattern.hint}`;
  }
  return { value: text.success };
}

/** Validating the preset-specific options (follows the chosen driver's declaration — data-driven). */
function parseTargetOptions(
  presetId: PresetId,
  driverKind: DriverKind,
  declaredOptions: Readonly<Record<string, OptionSpec>>,
  value: unknown,
): ResolvedOptions | Reason {
  const record = Schema.decodeUnknownResult(Schema.UndefinedOr(JsonRecord(" must be an object")))(
    value,
  );
  if (Result.isFailure(record)) {
    return { path: ["options"], issue: record.failure.issue };
  }
  const raw = record.success ?? {};
  const declared = Object.keys(declaredOptions);
  const unknown = unknownKeysRefusal(
    raw,
    declared,
    `the ${presetId} preset with the ${driverKind} driver accepts: ${declared.join(", ")}`,
  );
  if (unknown !== undefined) {
    return { path: ["options"], issue: reasonIssue(unknown) };
  }
  const options: Record<string, string | boolean> = {};
  for (const [key, spec] of Object.entries(declaredOptions)) {
    const given = raw[key];
    if (given === undefined) {
      if (spec.required) {
        return {
          path: ["options", key],
          issue: ` is required for the ${presetId} preset with the ${driverKind} driver${spec.values === undefined ? "" : ` (one of ${spec.values.join(", ")})`}`,
        };
      }
      continue;
    }
    const parsedValue = parseOptionValue(spec, given);
    if (isReason(parsedValue)) {
      return { path: ["options", key], issue: reasonIssue(parsedValue) };
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

/** `variables`: `"all"` (with an optional `exclude`), or a non-empty list of variable names. */
const VARIABLES_LIST = Schema.Array(Schema.Unknown)
  .annotate({ message: ' must be a non-empty array of variable names, or "all"' })
  .check(
    Schema.makeFilter((entries) =>
      entries.length > 0 &&
      entries.every((entry) => typeof entry === "string" && entry.trim().length > 0)
        ? undefined
        : ' must be a non-empty array of variable names, or "all"',
    ),
  );

/** `exclude`: an array of non-empty variable names (only alongside `"all"`). */
const EXCLUDE_LIST = Schema.Array(Schema.Unknown)
  .annotate({ message: " must be an array of variable names" })
  .check(
    Schema.makeFilter((entries) =>
      entries.every((entry) => typeof entry === "string" && entry.trim().length > 0)
        ? undefined
        : " must be an array of variable names",
    ),
  );

function parseVariables(
  record: Record<string, unknown>,
): { variables: readonly string[] | "all"; exclude: readonly string[] } | Reason {
  const raw = record["variables"];
  if (raw === "all") {
    if (record["exclude"] === undefined) {
      return { variables: "all", exclude: [] };
    }
    const exclude = field(record, "exclude", EXCLUDE_LIST);
    if (isReason(exclude)) {
      return exclude;
    }
    // The schema checked every entry is a non-empty string
    return { variables: "all", exclude: exclude.value as readonly string[] };
  }
  const list = field(record, "variables", VARIABLES_LIST);
  if (isReason(list)) {
    return list;
  }
  if (record["exclude"] !== undefined) {
    return { path: ["exclude"], issue: ' applies only when variables is "all"' };
  }
  const names = list.value as readonly string[];
  if (new Set(names).size !== names.length) {
    return { path: ["variables"], issue: " lists the same name more than once" };
  }
  return { variables: names, exclude: [] };
}

/** Interpreting `token: { environment, name }` (where the http driver's integration token lives). */
const TOKEN_REF = JsonRecord(
  ' must be an object of the form { "environment": "<environment ID>", "name": "<variable name>" }',
)
  .check(
    Schema.makeFilter(
      (record) =>
        unknownKeysRefusal(record, ["environment", "name"], "accepted: environment, name") ??
        undefined,
    ),
  )
  .pipe(
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

/** Interpreting `workflow: { file, ref?, command? }` (required when onPush is "workflow"). */
const WORKFLOW = JsonRecord(' must be an object of the form { "file": "<workflow file name>" }')
  .check(
    Schema.makeFilter(
      (record) =>
        unknownKeysRefusal(record, ["file", "ref", "command"], "accepted: file, ref, command") ??
        undefined,
    ),
  )
  .pipe(
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

/** Interpreting `receipts: { environment }` (where the receipt variables live — supplement 15 X3 (a)). */
const RECEIPTS = JsonRecord(' must be an object of the form { "environment": "<environment ID>" }')
  .check(
    Schema.makeFilter(
      (record) => unknownKeysRefusal(record, ["environment"], "accepted: environment") ?? undefined,
    ),
  )
  .pipe(
    Schema.decodeTo(
      Schema.Struct({
        environment: environmentId(
          " must be a maruhi environment ID (create it with `maruhi env create`)",
        ).annotateKey({
          messageMissingKey:
            " must be a maruhi environment ID (create it with `maruhi env create`)",
        }),
      }),
    ),
  );

/** Interpreting the exec driver's run surface (cwd / command). */
function parseExecDriver(
  record: Record<string, unknown>,
  spec: ExecPreset,
  configDir: string,
): TargetDriver | Reason {
  if (record["token"] !== undefined) {
    return {
      path: ["token"],
      issue: " applies only to the http driver (the exec driver uses the vendor CLI's own sign-in)",
    };
  }
  const cwd = field(
    record,
    "cwd",
    Schema.UndefinedOr(nonEmpty(" must be a non-empty relative path")),
  );
  if (isReason(cwd)) {
    return cwd;
  }
  const command = field(
    record,
    "command",
    Schema.UndefinedOr(nonEmpty(` must be a non-empty path to the installed ${spec.command} CLI`)),
  );
  if (isReason(command)) {
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
function parseHttpDriver(record: Record<string, unknown>, spec: HttpPreset): TargetDriver | Reason {
  for (const key of ["cwd", "command"] as const) {
    if (record[key] !== undefined) {
      return {
        path: [key],
        issue: " applies only to the exec driver (the http driver runs no vendor CLI)",
      };
    }
  }
  if (record["token"] === undefined) {
    return {
      path: ["token"],
      issue: ` is required for the http driver: { "environment": "<environment ID>", "name": "<variable name>" } naming the maruhi variable that holds ${spec.tokenHint}`,
    };
  }
  const token = field(record, "token", TOKEN_REF);
  if (isReason(token)) {
    return token;
  }
  return { kind: "http", spec, token: token.value };
}

/**
 * Resolving `driver` (omitted = the preset's default: exec when it has
 * one, else http). A config naming a driver the preset does not have is
 * refused with the reason (the declaration's `unavailable`) attached.
 */
function parseDriverKind(
  record: Record<string, unknown>,
  preset: SyncPreset,
): { readonly kind: DriverKind } | Reason {
  const declared = field(
    record,
    "driver",
    Schema.UndefinedOr(
      Schema.Literals(["exec", "http"]).annotate({
        message:
          ' must be "exec" (the installed vendor CLI; the default when the preset has one) or "http" (the vendor API with a token stored in maruhi)',
      }),
    ),
  );
  if (isReason(declared)) {
    return declared;
  }
  const kind = declared.value ?? defaultDriverOf(preset);
  const declaration = kind === "exec" ? preset.exec : preset.http;
  return isUnavailable(declaration)
    ? { path: ["driver"], issue: `: ${declaration.unavailable}; use "${defaultDriverOf(preset)}"` }
    : { kind };
}

/** Interpreting the target's shape (record, keys, preset, driver, environment). */
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
  | Reason {
  if (!TARGET_NAME.test(name)) {
    return "target names must start with an alphanumeric character, followed by up to 63 alphanumerics, _ or - (key under targets)";
  }
  const record = Schema.decodeUnknownResult(JsonRecord(" must be an object"))(value);
  if (Result.isFailure(record)) {
    return record.failure.issue;
  }
  const unknown = unknownKeysRefusal(
    record.success,
    TARGET_KEYS,
    `accepted: ${TARGET_KEYS.join(", ")}`,
  );
  if (unknown !== undefined) {
    return unknown;
  }
  const preset = field(
    record.success,
    "preset",
    Schema.Literals(Object.keys(SYNC_PRESETS)).annotate({
      message: ` must be one of ${Object.keys(SYNC_PRESETS).join(", ")}`,
    }),
  );
  if (isReason(preset)) {
    return preset;
  }
  const driverKind = parseDriverKind(record.success, SYNC_PRESETS[preset.value as PresetId]);
  if (isReason(driverKind)) {
    return driverKind;
  }
  const { kind } = driverKind;
  const environment = field(
    record.success,
    "environment",
    environmentId(" must be a maruhi environment ID"),
  );
  if (isReason(environment)) {
    return environment;
  }
  return {
    record: record.success,
    preset: SYNC_PRESETS[preset.value as PresetId],
    driverKind: kind,
    environment: environment.value,
  };
}

/** Reads the target's driver surface against the chosen driver's declaration (parseDriverKind already refused a missing declaration). */
function parseDriver(
  record: Record<string, unknown>,
  preset: SyncPreset,
  driverKind: DriverKind,
  configDir: string,
): TargetDriver | Reason {
  if (driverKind === "exec") {
    return isUnavailable(preset.exec)
      ? preset.exec.unavailable
      : parseExecDriver(record, preset.exec, configDir);
  }
  return isUnavailable(preset.http)
    ? preset.http.unavailable
    : parseHttpDriver(record, preset.http);
}

/** The driver's surface (exec = cwd / command, http = token) and the options verified against that driver's declaration. */
function parseDriverAndOptions(
  record: Record<string, unknown>,
  preset: SyncPreset,
  driverKind: DriverKind,
  configDir: string,
): { readonly driver: TargetDriver; readonly options: ResolvedOptions } | Reason {
  const driver = parseDriver(record, preset, driverKind, configDir);
  if (isReason(driver)) {
    return driver;
  }
  const options = parseTargetOptions(preset.id, driverKind, driver.spec.options, record["options"]);
  if (isReason(options)) {
    return options;
  }
  // The options' mutual consistency (the preset's `check` — Netlify's
  // context / branch / secret, GitHub's environment / app)
  const inconsistent = driver.spec.check?.(options) ?? null;
  return inconsistent === null
    ? { driver, options }
    : { path: ["options"], issue: `.${inconsistent}` };
}

/**
 * The token lives in the same environment as the sync source: an error
 * if it appears on the explicit list; under "all" it is silently
 * excluded (the structure guarantees the token is never carried to the
 * target).
 */
function excludeToken(
  name: string,
  selection: { readonly variables: readonly string[] | "all"; readonly exclude: readonly string[] },
  driver: TargetDriver,
  environment: string,
): readonly string[] | Reason {
  if (driver.kind !== "http" || driver.token.environment !== environment) {
    return selection.exclude;
  }
  if (selection.variables !== "all") {
    return selection.variables.includes(driver.token.name)
      ? {
          path: ["variables"],
          issue: ` lists the token variable (targets.${name}.token.name); the integration token is never copied to the target`,
        }
      : selection.exclude;
  }
  return selection.exclude.includes(driver.token.name)
    ? selection.exclude
    : [...selection.exclude, driver.token.name];
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
  isProduction: boolean,
  configDir: string,
): OnPush | null | Reason {
  const onPush = record["onPush"];
  if (onPush === undefined) {
    return record["workflow"] === undefined
      ? null
      : { path: ["workflow"], issue: ' applies only when onPush is "workflow"' };
  }
  const parsed = field(
    record,
    "onPush",
    Schema.Literals(["apply", "workflow"]).annotate({
      message:
        ' must be "apply" (sync from this machine right after `maruhi push`) or "workflow" (trigger the repository\'s workflow with gh so CI syncs); leave it out to sync only by hand',
    }),
  );
  if (isReason(parsed)) {
    return parsed;
  }
  if (parsed.value === "apply") {
    if (record["workflow"] !== undefined) {
      return { path: ["workflow"], issue: ' applies only when onPush is "workflow"' };
    }
    if (isProduction) {
      return {
        path: ["onPush"],
        issue:
          ' cannot be "apply" for a production target: production is written only by an explicit `maruhi sync apply --yes`. Use "workflow" to let CI write it under the --yes in the workflow file, or set production to false if the target is not production',
      };
    }
    return { kind: "apply" };
  }
  return parseWorkflow(record["workflow"], configDir);
}

/** Interpreting `workflow` (required when onPush is "workflow"). */
function parseWorkflow(value: unknown, configDir: string): OnPush | Reason {
  if (value === undefined) {
    return {
      path: ["workflow"],
      issue:
        ' is required when onPush is "workflow": { "file": "<workflow file name>" } naming the workflow that runs `maruhi ci sync` (it must have a workflow_dispatch trigger with a "target" input)',
    };
  }
  const workflow = field({ workflow: value }, "workflow", WORKFLOW);
  if (isReason(workflow)) {
    return workflow;
  }
  return {
    kind: "workflow",
    file: workflow.value.file,
    ref: workflow.value.ref,
    command: workflow.value.command ?? "gh",
    namedCommand: workflow.value.command !== undefined,
    cwd: configDir,
  };
}

const ROOT_KEYS = ["version", "project", "receipts", "targets"] as const;

function parseTarget(name: string, value: unknown, configDir: string): SyncTarget | Reason {
  const head = parseTargetHead(name, value);
  if (isReason(head)) {
    return head;
  }
  const { record, preset, driverKind, environment } = head;
  const selection = parseVariables(record);
  if (isReason(selection)) {
    return selection;
  }
  const production = field(
    record,
    "production",
    Schema.UndefinedOr(Schema.Boolean.annotate({ message: " must be true or false" })),
  );
  if (isReason(production)) {
    return production;
  }
  const driven = parseDriverAndOptions(record, preset, driverKind, configDir);
  if (isReason(driven)) {
    return driven;
  }
  const { driver, options } = driven;
  const exclude = excludeToken(name, selection, driver, environment);
  if (isReason(exclude)) {
    return exclude;
  }
  // Absent an explicit value, the preset decides (Vercel = production
  // environment, Workers = no named environment). Since it is a
  // misoperation guard, the default falls toward "production"
  const isProduction = production.value ?? preset.isProduction(options);
  const onPush = parseOnPush(record, isProduction, configDir);
  if (isReason(onPush)) {
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

/** Interpreting each target of `targets` and the checks spanning the whole config (the receipts environment, `project`). */
function parseTargets(
  record: Record<string, unknown>,
  configDir: string,
): ReadonlyMap<string, SyncTarget> | Reason {
  const raw = field(record, "targets", JsonRecord(" must be an object with at least one target"));
  if (isReason(raw)) {
    return raw;
  }
  if (Object.keys(raw.value).length === 0) {
    return { path: ["targets"], issue: " must be an object with at least one target" };
  }
  // The spanning checks read the config the earlier checks already
  // validated (receipts.environment, project)
  const receipts = field(record, "receipts", RECEIPTS);
  if (isReason(receipts)) {
    return receipts;
  }
  const header = parseConfigHeader(record, ROOT_KEYS);
  if (typeof header === "string") {
    return header;
  }
  const targets = new Map<string, SyncTarget>();
  for (const [name, value] of Object.entries(raw.value)) {
    const target = parseTarget(name, value, configDir);
    if (isReason(target)) {
      return { path: ["targets", name], issue: reasonIssue(target) };
    }
    const refused = targetSpan(name, target, receipts.value.environment, header.projectId);
    if (refused !== undefined) {
      return refused;
    }
    targets.set(name, target);
  }
  return targets;
}

/** A target's spanning refusals: the receipts environment as a source, and onPush without a `project` — undefined = the target stands. */
function targetSpan(
  name: string,
  target: SyncTarget,
  receiptsEnvironment: string | null,
  projectId: string | undefined,
): Reason | undefined {
  // Never make the receipts environment a sync source: blocks both the
  // shape where `maruhi run --env <receipts>` injects even receipt
  // variables into the child, and the shape that carries a receipt
  // itself to the target
  if (target.environment === receiptsEnvironment) {
    return {
      path: ["targets", name, "environment"],
      issue: ` is the receipts environment (${receiptsEnvironment}); receipts must live in an environment that is not synced`,
    };
  }
  // The post-push sync is only used with a config that names which
  // project it belongs to (stage 3's ruling B — never silently apply
  // cwd's config to a different project's push)
  if (target.onPush !== null && projectId === undefined) {
    return {
      path: ["targets", name, "onPush"],
      issue:
        ' needs the top-level "project": sync on push only uses a config that names its project (add it, or generate the config with `maruhi sync init --project <project ID>`)',
    };
  }
  return undefined;
}

/**
 * The document as a Schema: a JSON object, then the header fields, then
 * `receipts`, then `targets` — the same order the reasons ran in before
 * (the first one wins). `parseConfigHeader` (json-record.ts) stays the
 * header's check — it returns the reason's string, a verbatim filter
 * issue.
 */
const SyncDocument = (configDir: string) =>
  JsonRecord("the top level must be an object")
    .check(configHeader(ROOT_KEYS))
    .check(
      Schema.makeFilter((record) => {
        const receipts = field(record, "receipts", RECEIPTS);
        return isReason(receipts) ? receipts : undefined;
      }),
    )
    .check(
      Schema.makeFilter((record) => {
        const targets = parseTargets(record, configDir);
        return isReason(targets) ? targets : undefined;
      }),
    );

/** Interpreting the config JSON (the reason's string when invalid). */
export function parseSyncConfig(content: string, configDir: string): SyncConfig | Invalid {
  const json = Schema.decodeUnknownResult(Schema.fromJsonString(Schema.Unknown))(content);
  if (Result.isFailure(json)) {
    return "not valid JSON";
  }
  const decoded = Schema.decodeUnknownResult(SyncDocument(configDir))(json.success);
  if (Result.isFailure(decoded)) {
    return issueReason(decoded.failure.issue);
  }
  // The document's filters already ran the same pure steps — re-running
  // them on the validated record cannot produce a reason
  const parsed = parseSyncConfigDocument(decoded.success, configDir);
  if (isReason(parsed)) {
    throw new Error("sync-config: the document passed validation but failed to build");
  }
  return parsed;
}

/** The fused validation + build pass over a validated record (its checks are the document's filters). */
function parseSyncConfigDocument(
  record: Record<string, unknown>,
  configDir: string,
): SyncConfig | Reason {
  const header = parseConfigHeader(record, ROOT_KEYS);
  if (typeof header === "string") {
    return header;
  }
  const receipts = field(record, "receipts", RECEIPTS);
  if (isReason(receipts)) {
    return receipts;
  }
  const targets = parseTargets(record, configDir);
  return isReason(targets)
    ? targets
    : {
        version: 1,
        projectId: header.projectId,
        receiptsEnvironment: receipts.value.environment,
        targets,
      };
}

/** Loading and verifying `--config <file>` (default `maruhi.sync.json`). */
export function loadSyncConfig(path: string): Effect.Effect<SyncConfig, CliError> {
  return loadConfig(
    path,
    "sync config",
    "Create it with `maruhi sync init` (see the Deploy targets page in the docs), or pass --config <file>",
    (content) => parseSyncConfig(content, dirname(path)),
  ).pipe(Effect.map(({ parsed }) => parsed));
}

/**
 * The default config when it exists in the working directory (`maruhi push`
 * looks for it without being told): null when the file is absent, and the
 * same errors as {@link loadSyncConfig} when it exists but cannot be read or
 * is invalid — a broken config is reported, not skipped.
 */
export function loadSyncConfigIfPresent(path: string): Effect.Effect<SyncConfig | null, CliError> {
  return loadIfPresent(
    path,
    loadSyncConfig,
    `Cannot read the sync config ${path} (it exists but is not readable). Fix it, or pass --no-sync to push without syncing`,
  );
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
