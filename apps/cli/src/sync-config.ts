// `maruhi sync` のリポジトリ設定(SY2 第 1 段 — integration-options.md §3
// 補足 15 X1「同期の対応付け設定はリポジトリへ(非機密)」)。
//
// 「maruhi 環境 → 同期先(プリセット)/ 同期先の環境 / 運ぶ変数」の対応付けは
// 秘密ではなく、コードと一緒に版管理される設定。リポジトリアンカー
// (anchor.ts — `maruhi project anchor` の JSON を利用者がコミットする)と
// 同じ扱いで、CLI が永続化してよい「非機密の設定」の範囲内(CLAUDE.md)。
// 統合トークンは持たない(exec ドライバはベンダー CLI 自身のログインを使う —
// 補足 16)。レシートの置き場(環境 ID)もここで指す(X3 (a))。
//
// 形式: JSON 1 ファイル(既定 `maruhi.sync.json`、`--config` で差し替え)。
// version フィールドつき・未知のキーは拒否(打ち間違いを黙って無視しない)。
// 検証の文面は「どのキーが・なぜ」を言い、打たれた値そのものは出さない。

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { isEnvironmentId, isProjectId } from "@maruhi/core";
import { Effect } from "effect";

import { cliError, type CliError, usageError } from "./errors.ts";
import { parseJsonRecord } from "./json-record.ts";
import { type ExecPreset, EXEC_PRESETS, type OptionSpec, type PresetId } from "./sync-exec.ts";

/** Default location of the sync config, relative to the working directory. */
export const DEFAULT_SYNC_CONFIG_PATH = "maruhi.sync.json";

/** One deploy target: which maruhi environment goes where, and how. */
export interface SyncTarget {
  /** ターゲット名(設定のキー。レシート変数名の一部になる)。 */
  readonly name: string;
  readonly preset: ExecPreset;
  /** 復号する maruhi 環境 ID。 */
  readonly environment: string;
  /** 運ぶ変数名の明示リスト、または環境の全 active 変数(`"all"`)。 */
  readonly variables: readonly string[] | "all";
  /** `"all"` から除く名前(公開設定・プラットフォーム所有の資源 — 補足 13 W3)。 */
  readonly exclude: readonly string[];
  /** production 扱い(apply に `--yes` が要る — 補足 14 M4)。 */
  readonly production: boolean;
  /** ベンダー CLI の実行ディレクトリ(設定ファイルの場所からの相対を解決済み)。 */
  readonly cwd: string;
  /** 起動する実行体(既定はプリセットのコマンド名 = PATH 上の導入済み CLI)。 */
  readonly command: string;
  /** プリセット固有のオプション(プリセットの宣言で検証済み)。 */
  readonly options: Readonly<Record<string, string | boolean>>;
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

/** プリセット固有オプションの検証(宣言 `preset.options` に従う — データ駆動)。 */
function parseTargetOptions(
  preset: ExecPreset,
  value: unknown,
  path: string,
): Readonly<Record<string, string | boolean>> | Invalid {
  const record = value === undefined ? {} : value;
  if (!isRecord(record)) {
    return `${path} must be an object`;
  }
  const declared = Object.keys(preset.options);
  const unknown = unknownKeys(record, declared);
  if (unknown.length > 0) {
    return `${path} has unknown keys (${unknown.join(", ")}); the ${preset.id} preset accepts: ${declared.join(", ")}`;
  }
  const options: Record<string, string | boolean> = {};
  for (const [key, spec] of Object.entries(preset.options)) {
    const given = record[key];
    if (given === undefined) {
      if (spec.required) {
        return `${path}.${key} is required for the ${preset.id} preset${spec.values === undefined ? "" : ` (one of ${spec.values.join(", ")})`}`;
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
  "environment",
  "variables",
  "exclude",
  "production",
  "cwd",
  "command",
  "options",
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

/** ターゲットの実行面(production / cwd / command)の解釈。 */
function parseTargetExecution(
  record: Record<string, unknown>,
  path: string,
  preset: ExecPreset,
  configDir: string,
): { production: boolean | undefined; cwd: string; command: string } | Invalid {
  const production = record["production"];
  if (production !== undefined && typeof production !== "boolean") {
    return `${path}.production must be true or false`;
  }
  const cwd = optionalString(record, "cwd", path, "a non-empty relative path");
  if (typeof cwd === "string") {
    return cwd;
  }
  const command = optionalString(
    record,
    "command",
    path,
    `a non-empty path to the installed ${preset.command} CLI`,
  );
  if (typeof command === "string") {
    return command;
  }
  return {
    production,
    cwd: cwd.value === undefined ? configDir : join(configDir, cwd.value),
    command: command.value ?? preset.command,
  };
}

/** ターゲットの形(キー・プリセット・環境)の解釈。 */
function parseTargetHead(
  name: string,
  value: unknown,
): { record: Record<string, unknown>; preset: ExecPreset; environment: string } | Invalid {
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
  const presetId = value["preset"];
  // own-property 参照(`__proto__` 等の継承プロパティをプリセットに解決しない)
  const preset =
    typeof presetId === "string" && Object.hasOwn(EXEC_PRESETS, presetId)
      ? EXEC_PRESETS[presetId as PresetId]
      : undefined;
  if (preset === undefined) {
    return `${path}.preset must be one of ${Object.keys(EXEC_PRESETS).join(", ")}`;
  }
  const environment = value["environment"];
  if (typeof environment !== "string" || !isEnvironmentId(environment)) {
    return `${path}.environment must be a maruhi environment ID`;
  }
  return { record: value, preset, environment };
}

function parseTarget(name: string, value: unknown, configDir: string): SyncTarget | Invalid {
  const path = `targets.${name}`;
  const head = parseTargetHead(name, value);
  if (typeof head === "string") {
    return head;
  }
  const { record, preset, environment } = head;
  const selection = parseVariables(record, path);
  if (typeof selection === "string") {
    return selection;
  }
  const execution = parseTargetExecution(record, path, preset, configDir);
  if (typeof execution === "string") {
    return execution;
  }
  const options = parseTargetOptions(preset, record["options"], `${path}.options`);
  if (typeof options === "string") {
    return options;
  }
  return {
    name,
    preset,
    environment,
    variables: selection.variables,
    exclude: selection.exclude,
    // 明示が無ければプリセットの判定(Vercel = production 環境、Workers = 名前付き
    // 環境なし)。誤操作ガードなので既定は「production 寄り」に倒す
    production: execution.production ?? preset.isProduction(options),
    cwd: execution.cwd,
    command: execution.command,
    options,
  };
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
  const targets = new Map<string, SyncTarget>();
  for (const [name, value] of Object.entries(targetsRaw)) {
    const target = parseTarget(name, value, configDir);
    if (typeof target === "string") {
      return target;
    }
    // レシートの環境を同期元にしない: `maruhi run --env <receipts>` がレシート
    // 変数まで子へ注入する形と、レシート自身を同期先へ運ぶ形の両方を塞ぐ
    if (target.environment === receiptsEnvironment) {
      return `targets.${name}.environment is the receipts environment (${receiptsEnvironment}); receipts must live in an environment that is not synced`;
    }
    targets.set(name, target);
  }
  return { version: 1, projectId: project, receiptsEnvironment, targets };
}

/** `--config <file>`(既定 `maruhi.sync.json`)の読み込みと検証。 */
export function loadSyncConfig(path: string): Effect.Effect<SyncConfig, CliError> {
  return Effect.gen(function* () {
    const content = yield* Effect.tryPromise({
      try: () => readFile(path, "utf8"),
      catch: () =>
        cliError(
          `Cannot read the sync config ${path}. Create it in the repository (see the Deploy targets page in the docs), or pass --config <file>`,
        ),
    });
    const parsed = parseSyncConfig(content, dirname(path));
    if (typeof parsed === "string") {
      return yield* Effect.fail(cliError(`The sync config ${path} is invalid: ${parsed}`));
    }
    return parsed;
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
