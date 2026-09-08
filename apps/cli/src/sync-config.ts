// `maruhi sync` のリポジトリ設定(SY2 第 1 段 — integration-options.md §3
// 補足 15 X1「同期の対応付け設定はリポジトリへ(非機密)」。第 2 段で `driver` /
// `token` を追加)。
//
// 「maruhi 環境 → 同期先(プリセット)/ 同期先の環境 / 運ぶ変数」の対応付けは
// 秘密ではなく、コードと一緒に版管理される設定。リポジトリアンカー
// (anchor.ts — `maruhi project anchor` の JSON を利用者がコミットする)と
// 同じ扱いで、CLI が永続化してよい「非機密の設定」の範囲内(CLAUDE.md)。
// 統合トークンは持たない: exec ドライバはベンダー CLI 自身のログインを使い
// (補足 16)、http ドライバは maruhi の普通の変数を**指す**だけ(環境 ID と
// 変数名 — 補足 15 X2)。レシートの置き場(環境 ID)もここで指す(X3 (a))。
//
// 形式: JSON 1 ファイル(既定 `maruhi.sync.json`、`--config` で差し替え)。
// version フィールドつき・未知のキーは拒否(打ち間違いを黙って無視しない)。
// `version: 1` は第 1 段のまま(第 2 段のキーはすべて省略可で、第 1 段の設定は
// そのまま読める。第 1 段の CLI は第 2 段のキーを「未知のキー」として拒否する —
// 互換の方向は後方のみ。裁定 H)。第 3 段の `onPush` / `workflow` も同じ扱い
// (省略 = 手動同期のみ)。検証の文面は「どのキーが・なぜ」を言い、打たれた値
// そのものは出さない。

import { readFile, stat } from "node:fs/promises";
import { dirname, join } from "node:path";

import { isEnvironmentId, isProjectId } from "@maruhi/core";
import { Effect } from "effect";

import { cliError, type CliError, usageError } from "./errors.ts";
import { parseJsonRecord } from "./json-record.ts";
import type { ExecPreset } from "./sync-exec.ts";
import type { HttpPreset } from "./sync-http.ts";
import { type SyncPreset, SYNC_PRESETS } from "./sync-preset.ts";
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
      /** ベンダー CLI の実行ディレクトリ(設定ファイルの場所からの相対を解決済み)。 */
      readonly cwd: string;
      /** 起動する実行体(既定はプリセットのコマンド名 = PATH 上の導入済み CLI)。 */
      readonly command: string;
    }
  | {
      readonly kind: "http";
      readonly spec: HttpPreset;
      readonly token: TokenRef;
    };

/**
 * What `maruhi push` does for the target right after a push lands in its
 * source environment (SY2 第 3 段 — integration-options.md §3 補足 4 N1 /
 * 補足 7 P1): apply directly from the writer's CLI, or trigger the repository's
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
      /** Where `gh` runs (the config file's directory; gh resolves the repository from its git remote). */
      readonly cwd: string;
    };

/** One deploy target: which maruhi environment goes where, and how. */
export interface SyncTarget {
  /** ターゲット名(設定のキー。レシート変数名の一部になる)。 */
  readonly name: string;
  readonly preset: SyncPreset;
  readonly driver: TargetDriver;
  /** 復号する maruhi 環境 ID。 */
  readonly environment: string;
  /** 運ぶ変数名の明示リスト、または環境の全 active 変数(`"all"`)。 */
  readonly variables: readonly string[] | "all";
  /**
   * `"all"` から除く名前(公開設定・プラットフォーム所有の資源 — 補足 13 W3)。
   * 統合トークンが同期元と同じ環境にあれば、その名前は設定に無くてもここに入る
   * (トークンは運ばない — 構造で保証する)。
   */
  readonly exclude: readonly string[];
  /** production 扱い(apply に `--yes` が要る — 補足 14 M4)。 */
  readonly production: boolean;
  /** プリセット固有のオプション(選んだドライバの宣言で検証済み)。 */
  readonly options: ResolvedOptions;
  /** push 直後の自動同期(省略 = 手動のみ)。 */
  readonly onPush: OnPush | null;
}

/** The parsed repository sync config. */
export interface SyncConfig {
  readonly version: 1;
  /** 設定が属するプロジェクト(省略可。指定時は解決されたプロジェクトと照合する)。 */
  readonly projectId: string | undefined;
  /** レシート変数を置く環境 ID(補足 15 X3 (a))。 */
  readonly receiptsEnvironment: string;
  readonly targets: ReadonlyMap<string, SyncTarget>;
}

// ターゲット名は環境 ID と同じ字種に限る(レシート変数名 `sync-receipt:<name>` の
// 一部になり、表示・照合で中和の要らない形に保つ)
const TARGET_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

/** 検証失敗(理由の文字列)。値そのものは含めない。 */
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

/** 1 オプションの値の検証(宣言 spec に従う。不正なら理由)。 */
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
  return { value: given };
}

/** プリセット固有オプションの検証(選んだドライバの宣言に従う — データ駆動)。 */
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

/** 省略可能な非空文字列のキー(無ければ undefined、形が違えば理由)。 */
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

/** `token: { environment, name }` の解釈(http ドライバの統合トークンの置き場)。 */
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

/** exec ドライバの実行面(cwd / command)の解釈。 */
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
  };
}

/** http ドライバの資格面(token)の解釈。 */
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

/** ターゲットの形(キー・プリセット・ドライバ・環境)の解釈。 */
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
  const driverKind = driverKindOf(value["driver"]);
  if (driverKind === undefined) {
    return `${path}.driver must be "exec" (the installed vendor CLI; the default) or "http" (the vendor API with a token stored in maruhi)`;
  }
  const environment = value["environment"];
  if (typeof environment !== "string" || !isEnvironmentId(environment)) {
    return `${path}.environment must be a maruhi environment ID`;
  }
  return { record: value, preset, driverKind, environment };
}

/** プリセット id の解決(own-property 参照 — `__proto__` 等を解決しない)。 */
function presetOf(value: unknown): SyncPreset | undefined {
  return typeof value === "string" && Object.hasOwn(SYNC_PRESETS, value)
    ? SYNC_PRESETS[value as PresetId]
    : undefined;
}

/** `driver` の解決(省略 = exec)。 */
function driverKindOf(value: unknown): DriverKind | undefined {
  const driver = value ?? "exec";
  return driver === "exec" || driver === "http" ? driver : undefined;
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
  // 明示が無ければプリセットの判定(Vercel = production 環境、Workers = 名前付き
  // 環境なし)。誤操作ガードなので既定は「production 寄り」に倒す
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
 * `onPush` / `workflow` の解釈(第 3 段 — 裁定 B / C)。`"apply"` は書き手の CLI が
 * 直接 apply する形で、production ターゲットには**設定の段階で**拒む(production を
 * 書くのは人が `--yes` を打つ `maruhi sync apply` だけ — 第 1 段の裁定 J)。
 * `"workflow"` は `gh workflow run` で CI を起動する形で、値を書くのは CI の
 * workflow(そこに `--yes` が見える)なので production でも可。
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

/** `workflow: { file, ref?, command? }` の解釈(`onPush: "workflow"` のとき必須)。 */
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
  return { kind: "workflow", file, ref, command: command.value ?? "gh", cwd: configDir };
}

/** `workflow` の形(存在・オブジェクト・既知のキー)。 */
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
 * gh の argv に載る設定値(workflow 名・ref): 非空で、`-` で始まらない(フラグと
 * 読まれる形を設定で作らせない)。
 */
function ghArgument(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 && !value.startsWith("-")
    ? value
    : undefined;
}

/** ドライバの面(exec = cwd / command、http = token)と、そのドライバの宣言で検証したオプション。 */
function parseDriverAndOptions(
  record: Record<string, unknown>,
  path: string,
  preset: SyncPreset,
  driverKind: DriverKind,
  configDir: string,
): { readonly driver: TargetDriver; readonly options: ResolvedOptions } | Invalid {
  const driver =
    driverKind === "exec"
      ? parseExecDriver(record, path, preset.exec, configDir)
      : parseHttpDriver(record, path, preset.http);
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
  return typeof options === "string" ? options : { driver, options };
}

/**
 * トークンが同期元と同じ環境にある: 明示リストに載っていれば設定の誤り、"all" なら
 * 黙って除く(トークンを同期先へ運ばないことを構造で保証する)。
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

/** 設定 JSON の解釈(不正なら理由の文字列)。 */
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

/** `targets` の各ターゲットの解釈と、設定全体に掛かる検査(レシート環境・`project`)。 */
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
    // レシートの環境を同期元にしない: `maruhi run --env <receipts>` がレシート
    // 変数まで子へ注入する形と、レシート自身を同期先へ運ぶ形の両方を塞ぐ
    if (target.environment === root.receiptsEnvironment) {
      return `targets.${name}.environment is the receipts environment (${root.receiptsEnvironment}); receipts must live in an environment that is not synced`;
    }
    // push 直後の同期は「この設定がどのプロジェクトのものか」を名乗る設定にしか
    // 使わない(第 3 段の裁定 B — cwd の設定を別プロジェクトの push に黙って使わない)
    if (target.onPush !== null && root.project === undefined) {
      return `targets.${name}.onPush needs the top-level "project": sync on push only uses a config that names its project (add it, or generate the config with \`maruhi sync init --project <project ID>\`)`;
    }
    targets.set(name, target);
  }
  return targets;
}

/** `--config <file>`(既定 `maruhi.sync.json`)の読み込みと検証。 */
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

/** 名前でターゲットを引く(未知なら候補を添えて usage エラー相当の文面)。 */
export function requireSyncTarget(
  config: SyncConfig,
  name: string,
): Effect.Effect<SyncTarget, CliError> {
  const target = config.targets.get(name);
  if (target === undefined) {
    // 語が何も指していない = 書き方の誤り(2)。打たれた名前は出さず候補だけ言う
    return Effect.fail(
      usageError(
        `Unknown sync target (targets in the config: ${[...config.targets.keys()].join(", ")})`,
      ),
    );
  }
  return Effect.succeed(target);
}

/** 設定の `project` とフラグの照合(食い違いは書き方の誤り = 2)。 */
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
