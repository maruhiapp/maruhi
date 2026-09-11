// `maruhi sync init <target>`: リポジトリ設定(`maruhi.sync.json`)の生成
// (裁定 F)。
//
// 先例は `maruhi project anchor`(anchor.ts): 非機密の設定を **JSON として
// stdout に出し**、利用者がリダイレクトしてコミットする。ファイルは書かない
// (既存ファイルの上書き・マージの判断を CLI に持たせない — 2 つ目のターゲットは
// 手で足す。docs の表がキーを説明する)。ネットワークにも行かない: 入力はすべて
// フラグで、生成物は sync-config.ts の厳格なパーサを**そのまま通る**ことを
// 出す前に確かめる(通らなければ理由を添えて書き方の誤り = 2)。
//
// 値の既定: `variables` は省略時 `"all"`(+ Note で公開設定 / プラットフォーム
// 所有の資源を除くよう案内 — 補足 13 W3)、`production` はプリセットの判定に
// 任せる(明示は `--production`)。

import { Effect } from "effect";

import { type CliError, usageError } from "./errors.ts";
import { CliIo } from "./io.ts";
import { logNote } from "./notice.ts";
import { parseSyncConfig } from "./sync-config.ts";
import { defaultDriverOf, isUnavailable, SYNC_PRESETS } from "./sync-preset.ts";
import type { DriverKind, OptionSpec, PresetId } from "./sync-types.ts";

/** `maruhi sync init` の入力(すべて明示フラグ由来)。 */
export interface SyncInitInput {
  readonly target: string;
  readonly preset: string;
  readonly driver: string | undefined;
  /** 同期元の maruhi 環境 ID(`--env`)。 */
  readonly environment: string;
  /** レシート環境 ID(`--receipts`)。 */
  readonly receipts: string;
  readonly project: string | undefined;
  /** カンマ区切りの変数名(省略 = "all")。 */
  readonly variables: string | undefined;
  /** カンマ区切りの除外名(`variables` 省略時のみ)。 */
  readonly exclude: string | undefined;
  readonly production: boolean;
  readonly cwd: string | undefined;
  readonly command: string | undefined;
  readonly tokenEnvironment: string | undefined;
  readonly tokenName: string | undefined;
  /** push 直後の同期(`--on-push apply|workflow`)。 */
  readonly onPush: string | undefined;
  /** `--on-push workflow` の workflow ファイル名(`--workflow`)。 */
  readonly workflow: string | undefined;
  /** `key=value` の列(`--option`)。boolean オプションは true / false。 */
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

/** `--option key=value` の解釈(宣言の型に合わせて boolean に写す)。 */
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

/** 省略されたキーは JSON に出さない(`undefined` の値を落とす)。 */
function compact(record: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(record).filter(([, value]) => value !== undefined));
}

/** 1 ターゲットの JSON オブジェクト(キーの順は docs の表と同じ)。 */
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
    // exec は省略が既定。http は、それしか無いプリセットでも明示する(平文の行き先を読める形)
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

/** 設定オブジェクトを組み立て、厳格なパーサで検証してから JSON 文字列にする。 */
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
    // 生成物は厳格なパーサをそのまま通る(通らなければ、書き方の誤りとして理由を言う)
    const parsed = parseSyncConfig(json, ".");
    if (typeof parsed === "string") {
      return yield* Effect.fail(usageError(`The config would be invalid: ${parsed}`));
    }
    return json;
  });
}

/** `maruhi sync init`: 設定 JSON を stdout に出す(コマンドの出力 — 決定 9)。 */
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
