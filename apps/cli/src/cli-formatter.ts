// maruhi の診断を **Effect の機構(`CliOutput.Formatter`)として**実装する
// (ADR-0016 決定 3)。文言は英語(ADR-0017)。
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
// **`InvalidValue.expected`**: 上流の `Param.filter` は `expected: onNone(a)` を
// 組み立てるので、`onNone` に値を埋め込む書き方(effect 自身の JSDoc 例が
// `Expected even number, got ${n}`)をすると期待値の側から平文が漏れる。
// **こちらが書いた文面と一致したときだけ**出す。

import type { HelpDoc } from "effect/unstable/cli";
import { CliError, CliOutput } from "effect/unstable/cli";

import { RUN_COMMAND_REQUIRED } from "./run.ts";

/**
 * 診断の文面を組むためのコマンド宣言(検査そのものは Flag / Argument 側)。
 *
 * 中身は effect-cli.ts が**コマンド定義そのものから導く**(手書きの写しを
 * 持たない — 宣言を足したときに診断だけ古いまま残る形を作らない)。
 */
export interface CommandSpec {
  readonly flags: readonly string[];
  readonly positionals: readonly string[];
  /** 入れ子サブコマンドを持つ段の、サブコマンド名の一覧(葉は省略)。 */
  readonly subcommands?: readonly string[];
  /**
   * 余分な位置引数の拒否に添えるコマンド固有の直し方(push の stdin 案内)。
   * 中身を伏せる以上、直し方を添えないと打ち間違いを直せない(args.test.ts の
   * 旧ケースが固定していた規律)。
   */
  readonly strayHint?: string;
}

/** 空・空白だけの値を拒む Schema の文面(宣言側とここで同じ定数を使う)。 */
export const NON_BLANK_MESSAGE = "a non-empty value (whitespace-only values are not accepted)";

/**
 * そのまま出してよい `expected` の全体集合。
 *
 * ここに無い文面は**こちらが書いたものではない**(= 値を含みうる)ので出さない。
 */
const SAFE_EXPECTATIONS: ReadonlySet<string> = new Set([NON_BLANK_MESSAGE]);

/** 組み込みのグローバルフラグ(CliConfig の builtIns — 宣言の表には現れない)。 */
const GLOBAL_FLAGS = ["--help", "--version"] as const;

function bareName(name: string): string {
  return name.replace(/^-+/, "");
}

/** 表示用のコマンド名(root 段 — 空のキー — は `maruhi` 単体)。 */
function commandLabel(commandKey: string): string {
  return commandKey === "" ? "maruhi" : `maruhi ${commandKey}`;
}

function unrecognizedOptionMessage(
  error: CliError.UnrecognizedOption,
  specs: Readonly<Record<string, CommandSpec>>,
  commandKey: string,
): string {
  // 宣言の選択は**上流が報告した段**(`error.command` — どの段でそのフラグが
  // 未宣言だったか)を優先する。振り分けのキーは argv からの推定なので、
  // `maruhi env --new-epoch rotate dev` のように**親の段に書いたフラグ**でも
  // 葉(`env rotate`)へ解決してしまい、拒否したフラグを「受け付ける一覧」に
  // 載せる自己矛盾の診断になる(Bugbot 指摘)。親の段の宣言を引ければ、
  // 置き場所(サブコマンドの後ろ)の案内に正しく分岐する
  const errorKey = (error.command ?? []).slice(1).join(" ");
  // root(errorKey が空)も root の spec(空のキー)で組む: `maruhi --show
  // pull` のようにフラグをコマンド名より前に書いた形で、振り分けの葉
  // (commandKey)の宣言へ落とすと「--show を拒否しつつ受け付ける一覧に
  // --show を載せる」自己矛盾の診断になる。root spec は置き場所(サブコマンド
  // の後ろ)の案内に分岐する
  const spec = specs[errorKey] ?? specs[commandKey];
  const errorCommandKey = specs[errorKey] !== undefined ? errorKey : commandKey;
  // 位置引数の名前をオプションとして書いた形は、直し方が違う
  const option = bareName(error.option);
  if (spec?.positionals.includes(option) === true) {
    return `--${option} is a positional argument (it cannot be written as a flag). Write the value as a positional argument instead`;
  }
  // 解決済みの段の宣言に**在る**フラグが未宣言として報告された = 書いた位置が
  // サブコマンドより前(`audit --limit 5 list` — 上流は親のローカルフラグを
  // サブコマンドへ継承しない)。「存在しない」とも「受け付ける一覧」とも
  // 言わない — 同じフラグを拒否しつつ一覧に載せる自己矛盾の診断になる
  // (レビュー第 2 巡の指摘)。置き場所だけを案内する
  if (spec?.flags.includes(option) === true) {
    return `Unknown flag position (--${option} belongs after the subcommand — e.g. ${commandLabel(errorCommandKey)} --${option} …)`;
  }
  const guess = error.suggestions[0];
  if (guess !== undefined) {
    return `Unknown flag (did you mean --${bareName(guess)}?)`;
  }
  return undeclaredFlagMessage(spec, errorCommandKey);
}

/** 候補も出せない未宣言フラグの文面(段の種類 — 親 / 葉 — で直し方が違う)。 */
function undeclaredFlagMessage(spec: CommandSpec | undefined, commandKey: string): string {
  // 入れ子の段(サブコマンドを持つ親)は**普通は**自分のフラグを持たない。
  // gunshi 時代は操作名より前に書いたフラグも通ったため、その形で来た利用者に
  // 「フラグが存在しない」と嘘をつかず、**置き場所**を案内する。例外は
  // 親自身が宣言を持つ段(bare `audit` = list)で、そちらは葉と同じく
  // 受け付けるフラグの一覧を出す
  const subcommands = (spec?.flags.length ?? 0) === 0 ? (spec?.subcommands ?? []) : [];
  const first = subcommands[0];
  if (first !== undefined) {
    return `Unknown flag (${commandLabel(commandKey)} itself takes only ${GLOBAL_FLAGS.join(" / ")} — write the subcommand first and its flags after it, e.g. ${commandLabel(commandKey)} ${first} --flag …)`;
  }
  // 実行時に混ぜられるグローバル(--help / --version)は宣言の表に現れない
  // ので、ここで補う(無いと、実在するフラグが一覧から抜ける)
  const declared = [...(spec?.flags ?? []).map((name) => `--${name}`), ...GLOBAL_FLAGS];
  return `Unknown flag (flags this command accepts: ${declared.join(" ")})`;
}

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
    return `Flag --${name} was specified more than once. Which occurrence you meant cannot be determined, so the invocation is rejected — write it exactly once`;
  }
  if (error.expected.includes("at least") || error.expected === RUN_COMMAND_REQUIRED) {
    return RUN_COMMAND_REQUIRED;
  }
  const expectation = error.expected.replace("Schema validation failed: ", "");
  const detail = SAFE_EXPECTATIONS.has(expectation) ? ` (expected: ${expectation})` : "";
  return error.kind === "argument"
    ? `Unacceptable value for positional argument ${name}${detail}`
    : `Unacceptable value for flag --${name}${detail}`;
}

/**
 * `UserError` は**こちらが書いた `userMessage` のときだけ**出す。
 *
 * `message` は `userMessage` が空だと **`cause` の message** へ落ちる(上流の
 * 宣言どおり)。`cause` は `Flag.mapEffect` / `Argument.mapEffect` に渡した
 * 任意の失敗なので、打たれた値を含みうる — `InvalidValue.expected` を
 * {@link SAFE_EXPECTATIONS} で塞いだのと同じ理由で、素通しにはしない。
 *
 * 現行の宣言(effect-cli.ts)は `mapEffect` を使っていないので到達しないが、
 * **足した瞬間に穴が開く**位置なのでここで縛っておく。
 */
function userErrorMessage(error: CliError.UserError): string {
  const authored = error.userMessage ?? "";
  return authored === "" ? "Invalid command-line arguments" : authored;
}

/**
 * 不明なサブコマンド。候補(編集距離)があればそれを、無ければ**その段が取る
 * サブコマンドの一覧**を出す — gunshi 時代の「不明な操作です(create | rotate |
 * diff)」と同じ水準を保つ(打ち間違いの直し先を探させない)。
 */
function unknownSubcommandMessage(
  error: CliError.UnknownSubcommand,
  specs: Readonly<Record<string, CommandSpec>>,
): string {
  const guess = error.suggestions[0];
  if (guess !== undefined) {
    return `Unknown subcommand (did you mean ${guess}?)`;
  }
  // 親の段(`["maruhi", "env"]` → `env`)の宣言からサブコマンド一覧を引く
  const parentKey = (error.parent ?? []).slice(1).join(" ");
  const known = specs[parentKey]?.subcommands ?? [];
  const listed = known.length === 0 ? "" : ` (expected one of: ${known.join(" | ")})`;
  return `Unknown subcommand${listed}`;
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
    return unrecognizedOptionMessage(error, specs, commandKey);
  }
  if (error instanceof CliError.UnexpectedArgument) {
    return unexpectedArgumentMessage(error, spec, commandKey);
  }
  if (error instanceof CliError.InvalidValue) {
    return invalidValueMessage(error);
  }
  if (error instanceof CliError.MissingArgument) {
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
  return "Invalid command-line arguments";
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
      helpRequested ? fallback.formatHelpDoc(doc) : `Usage: ${doc.usage}`,
    // `--version` は**版番号だけ**を出す(gunshi 時代からの契約 —
    // version.test.ts が固定。`V=$(maruhi --version)` がそのまま使える形)
    formatVersion: (_name: string, version: string) => version,
    formatError: describe,
    formatCliError: describe,
    // コマンド名が解決できなかった実行では、フラグは root の宣言と突き合わ
    // されるため、正しく綴られたフラグまで不明として並ぶ。誤りはコマンド名の
    // 方なので、綴りの合っているフラグを探させない(gunshi 時代の
    // usageErrorMessages と同じ規律)
    formatErrors: (errors: ReadonlyArray<CliError.CliError>) => {
      // 抑えるのは **root 段**(コマンド名そのものが解決できなかった実行)
      // だけ: 深い段の UnknownSubcommand(`server abc` の abc)では、親の段に
      // 書いたフラグへの置き場所の案内が同時に要る
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

/** Provides {@link maruhiFormatter} as a layer (`CliOutput.layer`). */
export function formatterLayer(
  commandKey: string,
  specs: Readonly<Record<string, CommandSpec>>,
  helpRequested: boolean,
) {
  return CliOutput.layer(maruhiFormatter(commandKey, specs, helpRequested));
}
