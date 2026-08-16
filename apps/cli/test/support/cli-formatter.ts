// maruhi の診断を **Effect の機構(`CliOutput.Formatter`)として**実装する。
//
// なぜ差し替えが要るか: effect/unstable/cli の既定の文面は**打たれた値を
// そのまま含む**(`Invalid value for flag --env: "  "` /
// `Unexpected positional argument: "..."`)。位置引数・オプション値には平文が
// 書かれうる(`maruhi push API_KEY "$SECRET"` の形)ため、既定のままでは
// stderr → CI / エージェントのログへ平文が流れる。
//
// なぜ**ランナー側の自前描画ではなく** Formatter なのか: 描画の呼び出しは
// effect/unstable/cli 自身が持つ(`showHelp` → `Console`)。Formatter を
// 差し込めば、その経路に乗ったまま**文面だけ**を maruhi の語彙にできる。
// ランナーに if 文を書き足す形にすると、上流が描画を増やしたときに
// 素通りする経路ができる。
//
// 出してよいのは**こちらの語彙**だけ: 宣言名・候補・個数。危険なのは
// `UnexpectedArgument.arguments` と `InvalidValue.value`、そして
// **`InvalidValue.expected`**(レビュー指摘): 上流の `Param.filter` は
// `expected: onNone(a)` を組み立てるので、`onNone` に値を埋め込む書き方
// (effect 自身の JSDoc 例が `Expected even number, got ${n}`)をすると
// 期待値の側から平文が漏れる。**こちらが書いた文面と一致したときだけ**出す。

import type { HelpDoc } from "effect/unstable/cli";
import { CliError, CliOutput } from "effect/unstable/cli";

/** 診断の文面を組むためのコマンド宣言(検査そのものは Flag / Argument 側)。 */
export interface CommandSpec {
  readonly flags: readonly string[];
  readonly positionals: readonly string[];
  /** 余分な引数を拒否するときに添えるコマンド固有の助言。 */
  readonly strayHint?: string | undefined;
}

/** `maruhi run` の実行対象が無い / 空のときの案内(src/run.ts と同じ文面)。 */
export const RUN_COMMAND_REQUIRED =
  "実行するコマンドを `--` の後に指定してください(例: maruhi run -- printenv MY_VAR)";

/** 空・空白だけの値を拒む Schema の文面(宣言側とここで同じ定数を使う)。 */
export const NON_BLANK_MESSAGE = "空でない値(空白だけの値も受け付けません)";

/**
 * そのまま出してよい `expected` の全体集合。
 *
 * ここに無い文面は**こちらが書いたものではない**(= 値を含みうる)ので出さない。
 */
const SAFE_EXPECTATIONS: ReadonlySet<string> = new Set([NON_BLANK_MESSAGE]);

function bareName(name: string): string {
  return name.replace(/^-+/, "");
}

function unrecognizedOptionMessage(
  error: CliError.UnrecognizedOption,
  spec: CommandSpec | undefined,
): string {
  // 位置引数の名前をオプションとして書いた形は、直し方が違う
  const option = bareName(error.option);
  if (spec?.positionals.includes(option) === true) {
    return `--${option} は位置引数です(オプションとしては指定できません)。値は位置引数として並べてください`;
  }
  const guess = error.suggestions[0];
  if (guess !== undefined) {
    return `不明なオプションです(--${bareName(guess)} のことですか?)`;
  }
  const declared = (spec?.flags ?? []).map((name) => `--${name}`);
  return `不明なオプションです(このコマンドが取るオプション: ${declared.join(" ")})`;
}

function unexpectedArgumentMessage(
  error: CliError.UnexpectedArgument,
  spec: CommandSpec | undefined,
  commandKey: string,
): string {
  const takesNone = spec === undefined || spec.positionals.length === 0;
  const shape = takesNone
    ? `maruhi ${commandKey} は位置引数を取りません`
    : `maruhi ${commandKey} が取る位置引数は ${spec.positionals.join(" ")} だけです`;
  return `余分な引数です(${error.arguments.length} 個。中身は表示しません — 平文の値が混ざりうるため)。${shape}${spec?.strayHint ?? ""}`;
}

/**
 * 値の伴う `InvalidValue` を、**値を出さずに**説明する。
 *
 * `expected` は「宣言側の語彙だから安全」とは限らない(上記のとおり
 * `Param.filter` は `onNone(a)` をそのまま `expected` にする)。判定できるのは
 * 上流が組み立てる定型(`at most` / `at least`)と、**こちらが書いた定数**だけ。
 */
function invalidValueMessage(error: CliError.InvalidValue): string {
  const name = bareName(error.option);
  if (error.expected.includes("at most")) {
    return `オプション --${name} を複数回指定しています。どちらの指定を意図したか読み取れないため受け付けません — 1 回だけ書いてください`;
  }
  if (error.expected.includes("at least") || error.expected === RUN_COMMAND_REQUIRED) {
    return RUN_COMMAND_REQUIRED;
  }
  const expectation = error.expected.replace("Schema validation failed: ", "");
  const detail = SAFE_EXPECTATIONS.has(expectation) ? `(${expectation})` : "";
  return error.kind === "argument"
    ? `位置引数 ${name} の値が受け付けられません${detail}`
    : `オプション --${name} の値が受け付けられません${detail}`;
}

function unknownSubcommandMessage(error: CliError.UnknownSubcommand): string {
  const guess = error.suggestions[0];
  return `不明なコマンドです${guess === undefined ? "" : `(${guess} のことですか?)`}`;
}

/**
 * Renders one CLI error in maruhi's vocabulary, never echoing typed values.
 *
 * 判定は instanceof で行う(`_tag` への直接アクセスは oxlint が禁止する —
 * src/failure.ts と同じ規律)。
 */
export function describeError(
  error: CliError.CliError,
  commandKey: string,
  specs: Readonly<Record<string, CommandSpec>>,
): string {
  const spec = specs[commandKey];
  if (error instanceof CliError.UnrecognizedOption) {
    return unrecognizedOptionMessage(error, spec);
  }
  if (error instanceof CliError.UnexpectedArgument) {
    return unexpectedArgumentMessage(error, spec, commandKey);
  }
  if (error instanceof CliError.InvalidValue) {
    return invalidValueMessage(error);
  }
  if (error instanceof CliError.MissingArgument) {
    return `位置引数 ${bareName(error.argument)} を指定してください`;
  }
  if (error instanceof CliError.MissingOption) {
    return `オプション --${bareName(error.option)} を指定してください`;
  }
  if (error instanceof CliError.UnknownSubcommand) {
    return unknownSubcommandMessage(error);
  }
  if (error instanceof CliError.UserError) {
    return error.message;
  }
  return "引数の書き方が正しくありません";
}

/**
 * Builds the `CliOutput.Formatter` used by maruhi.
 *
 * `helpRequested` で本文の量を変える: `--help` を明示した実行は既定の
 * フォーマッタの全文(ヘルプは maruhi の出力であって診断ではない)、
 * 書き方の誤りに添えるのは**使い方の 1 行だけ**にする。誤りのたびに全文が
 * 出ると、肝心の診断が埋もれる(gunshi 時代も同じ理由でヘルプを止めていた)。
 */
function maruhiFormatter(
  commandKey: string,
  specs: Readonly<Record<string, CommandSpec>>,
  helpRequested: boolean,
): CliOutput.Formatter {
  const describe = (error: CliError.CliError): string =>
    `maruhi: ${describeError(error, commandKey, specs)}`;
  const fallback = CliOutput.defaultFormatter({ colors: false });
  return {
    formatHelpDoc: (doc: HelpDoc.HelpDoc) =>
      helpRequested ? fallback.formatHelpDoc(doc) : `使い方: ${doc.usage}`,
    formatVersion: fallback.formatVersion,
    formatError: describe,
    formatCliError: describe,
    formatErrors: (errors: ReadonlyArray<CliError.CliError>) => errors.map(describe).join("\n"),
  };
}

/** Provides {@link maruhiFormatter} as a layer (`CliOutput.layer`). */
export function formatterLayer(
  commandKey: string,
  specs: Readonly<Record<string, CommandSpec>>,
  helpRequested: boolean,
) {
  return CliOutput.layer(maruhiFormatter(commandKey, specs, helpRequested));
}
