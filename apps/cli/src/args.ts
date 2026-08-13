// 引数の**書き方**の検査(全コマンド共通)と、gunshi の usage エラーの整形。
//
// gunshi 0.37.1 は「宣言と食い違う書き方」をいくつか黙って通す。いずれも
// **書いたことと逆の結果**になりうるので、値を扱う前に落とす:
//
// 1. 未宣言のオプション(`maruhi pull --shwo`)は無視される = `--show` なしで
//    実行される。位置引数の名前をオプションとして書いた形(`env create dev
//    --environment-id prod`)も値が捨てられる。どちらも `CliOptions.strict`
//    (cli.ts)が **runner 実行前**の検証エラーにするので、ここでは扱わない
//    — 診断文だけ usageErrorMessages が受け持つ
// 2. boolean へのインライン値(`--show=false`)は値を**読まずに true** になる
// 3. boolean への空白区切りの値(`--show false`)は値が消費されないため
//    「フラグ有効 + 余分な位置引数」になる
//
// 2 / 3 は**宣言済み**オプションの書き方の問題なので strict では塞がらない。
// 判定材料は引数表(`ctx.args`)そのもの — 手書きの一覧と二重管理にすると、
// 次に増えたオプションが実装済みなのに拒否される。
//
// 診断の規律: **拒否した引数の中身は書き出さない**。拒否されるのは「値を
// オプション / 位置引数として書いてしまった」形でもありうるので、平文が
// stderr → CI・エージェントのログへ流れる経路を作らない(CLAUDE.md: 平文値・
// 鍵素材をログ・エラーメッセージに出力しない)。
//
// 例外は 2 つだけで、いずれも**こちらの語彙**に収まるものに限る:
// (a) オプション / コマンド名の綴り(echoableSpelling — 英字とハイフンだけ、
//     数字や `_` を含む「値らしい」綴りは伏せる)
// (b) 引数表由来の名前(宣言済みの位置引数名・オプション名・期待する型)
// コマンドが意味的に受け取る識別子(config のキー・action)は値ではないので
// 各コマンドが表示してよいが、端末出力の中和(displayText)は必ず通す。

import {
  ArgsValidationErrorKeys,
  isArgsValidationError,
  isCommandNotFoundError,
  parseArgs,
} from "gunshi";

import { displayText } from "./display.ts";

/** ブランド名 = 表示に使うコマンド名(`mh` で起動しても表記は maruhi)。 */
const CLI_NAME = "maruhi";

/** 引数表の 1 エントリ(判定に使う部分だけ)。 */
interface ArgSchemaShape {
  readonly type?: string | undefined;
  readonly short?: string | undefined;
}

/** gunshi の引数表(`ctx.args`)。宣言済みオプションと位置引数の完全な表。 */
export type ArgTable = Readonly<Record<string, ArgSchemaShape>>;

/** gunshi の引数トークン(`ctx.tokens`)。打たれたとおりの並び。 */
export interface ArgTokenShape {
  readonly kind: string;
  readonly name?: string | undefined;
  readonly rawName?: string | undefined;
  readonly value?: string | undefined;
  readonly inlineValue?: boolean | undefined;
}

/**
 * 検査に必要な CommandContext の部分。コマンドごとに型の違う `values` を
 * 含めないので、1 つの検査を全コマンドへ適用できる。
 *
 * `--` の後ろは **`ctx.rest` を使わず**トークンから組み直す(下記
 * restArguments を参照 — 空文字列の引数が rest から落ちて positionals へ
 * 紛れ込むため)。位置引数の数もその紛れ込みを引いて数える。
 */
export interface ArgCheckContext {
  readonly args: ArgTable;
  readonly tokens: readonly ArgTokenShape[];
  readonly positionals: readonly string[];
  readonly commandPath: readonly string[];
}

/** 打たれたとおりの綴りで返す(`-x` を `--x` と書き換えて出さない)。 */
export function typedName(token: ArgTokenShape): string {
  return displayText(token.rawName ?? `--${token.name ?? ""}`);
}

/**
 * `--` の後ろの引数(`maruhi run` が子プロセスへ渡すもの)。
 *
 * gunshi の `ctx.rest` は使えない: 値が truthy のときだけ rest へ入れるため
 * (`resolveArgs` の `terminated && token.value`)、**空文字列の引数が rest から
 * 落ちて `ctx.positionals` へ紛れ込む**(実測: `run -- printenv "" x` →
 * rest `["printenv","x"]` / positionals `["run",""]`)。子プロセスの引数が
 * 黙って 1 つ減り、余分な位置引数の検査も誤爆する。トークンから組み直す。
 */
export function restArguments(tokens: readonly ArgTokenShape[]): readonly string[] {
  const rest: string[] = [];
  let terminated = false;
  for (const token of tokens) {
    if (token.kind === "option-terminator") {
      terminated = true;
      continue;
    }
    if (terminated) {
      rest.push(token.value ?? "");
    }
  }
  return rest;
}

/**
 * `--` より前の位置引数の数(先頭にサブコマンド名を含む)。
 *
 * トークンを数えるだけでは足りない: パーサは引数表を知らないので、
 * `--reason x` の `x` も positional トークンになる(`ctx.positionals` は
 * 引数表を見て値として消費した後の並び)。一方 `ctx.positionals` には
 * **`--` の後ろから落ちてきた分**(gunshi が rest へ載せない空文字列)が
 * 紛れ込む。そこで「引数表を通した並びから、紛れ込んだ分を引く」で数える。
 */
function positionalCount(ctx: ArgCheckContext): number {
  const leakedFromRest = restArguments(ctx.tokens).filter((value) => value === "").length;
  return ctx.positionals.length - leakedFromRest;
}

function namesOfType(args: ArgTable, type: string): readonly string[] {
  return Object.entries(args)
    .filter(([, schema]) => schema.type === type)
    .map(([name]) => name);
}

/**
 * boolean として書かれうる綴り。長い名前と短縮形を**別々に**持つ:
 * 1 つの集合に混ぜると、ある boolean の短縮形と同じ名前を持つ別のオプション
 * (例: 長い名前が `h` の string)を boolean と取り違える。
 */
function booleanSpellings(args: ArgTable): {
  readonly names: ReadonlySet<string>;
  readonly shorts: ReadonlySet<string>;
} {
  const names = new Set<string>();
  const shorts = new Set<string>();
  for (const [name, schema] of Object.entries(args)) {
    if (schema.type !== "boolean") {
      continue;
    }
    names.add(name);
    if (schema.short !== undefined) {
      shorts.add(schema.short);
    }
  }
  return { names, shorts };
}

type BooleanSpellings = ReturnType<typeof booleanSpellings>;

/** そのトークンは boolean オプションを指しているか(短縮形は綴りで見分ける)。 */
function isBooleanToken(token: ArgTokenShape, booleans: BooleanSpellings): boolean {
  if (token.kind !== "option" || token.name === undefined) {
    return false;
  }
  return token.rawName?.startsWith("--") === false
    ? booleans.shorts.has(token.name)
    : booleans.names.has(token.name);
}

// 「値として書かれた」と読める語。boolean の直後に置かれたこれらは、位置引数
// ではなくフラグの値のつもりと判断する
const BOOLEAN_LITERALS = new Set(["true", "false", "0", "1", "yes", "no", "on", "off"]);

/**
 * 表示用のコマンド名。エントリコマンドは**自分自身の名前でも**サブコマンドと
 * して登録される(gunshi の createInitialSubCommands)ため、`maruhi maruhi`
 * と二重に書かない。
 */
function commandLabel(commandPath: readonly string[]): string {
  const path = commandPath[0] === CLI_NAME ? commandPath.slice(1) : commandPath;
  return [CLI_NAME, ...path].join(" ");
}

/** boolean へ値を付けたときの共通文面(インライン形・空白区切り形で同じ)。 */
function booleanTakesNoValue(token: ArgTokenShape): string {
  const typed = typedName(token);
  return `${typed} は値を取りません(指定した値は無視され、フラグは有効として扱われます)。有効にするなら値なしで ${typed} と書き、無効にするならオプション自体を外してください`;
}

/**
 * boolean オプションの**直後**に置かれた真偽値らしい語(`--new-epoch false`)の
 * 拒否。gunshi は boolean の値を消費しないため、この語は位置引数として残る。
 *
 * 個数だけの検査では足りない: 必須の位置引数が空いていると、その語が**位置引数
 * として受理されてしまう**。`maruhi env rotate --reason x --new-epoch false` は
 * 環境 `false` のローテーション(フラグは有効のまま = 書いたことと逆)になり、
 * チェーンは append-only なので取り消せない。
 *
 * `--new-epoch dev` のように「フラグの後ろに置いた本物の位置引数」は正当な
 * 書き方なので、真偽値として読める語だけを拒否する。
 */
function booleanLiteralRejection(ctx: ArgCheckContext, booleans: BooleanSpellings): string | null {
  let previous: ArgTokenShape | undefined;
  for (const token of ctx.tokens) {
    if (token.kind === "option-terminator") {
      break;
    }
    if (
      token.kind === "positional" &&
      previous !== undefined &&
      isBooleanToken(previous, booleans) &&
      BOOLEAN_LITERALS.has((token.value ?? "").toLowerCase())
    ) {
      return booleanTakesNoValue(previous);
    }
    previous = token;
  }
  return null;
}

/**
 * boolean オプションへのインライン値(`--new-epoch=false`)の拒否。gunshi は値を
 * 読まずにフラグを true にするため、放置すると書いたことと逆の結果になる
 * (チェーンは append-only なので取り消せない)。
 */
function inlineValueRejection(ctx: ArgCheckContext, booleans: BooleanSpellings): string | null {
  // 短縮形へのインライン値(`-s=false`)は「名前つきトークン」+「**名前なしの**
  // インライン値トークン」の 2 つに割れる(args-tokens 0.28.1 実測)。名前なし
  // トークンは直前のオプションのものなので、そこまで遡って判定する
  let named: ArgTokenShape | undefined;
  for (const token of ctx.tokens) {
    if (token.kind !== "option") {
      named = undefined;
      continue;
    }
    if (token.name !== undefined) {
      named = token;
    }
    if (token.inlineValue !== true || named === undefined || !isBooleanToken(named, booleans)) {
      continue;
    }
    return booleanTakesNoValue(named);
  }
  return null;
}

/**
 * 余分な引数の共通文面。**中身は決して出さない**(個数と形だけを言う)。
 *
 * 拒否した引数は任意のユーザー入力であり、平文の値が混ざりうる —
 * `maruhi push API_KEY "$SECRET"`(値は stdin から読むので、この書き方は
 * 余分な引数になる)がその形。診断は CI やエージェントのログに残るため、
 * 打ち間違いを教えるために平文をもう一度書き出す取引はしない。
 */
function strayArgumentsMessage(count: number, shape: string, suffix = ""): string {
  return `余分な引数です(${count} 個。中身は表示しません — 平文の値が混ざりうるため)。${shape}${suffix}`;
}

/**
 * 余分な位置引数の拒否。boolean は**空白区切りの値を読まない**ため、
 * `--show false` は「フラグ有効 + 位置引数 "false"」になり、無効にした
 * つもりが値の表示になる。想定数は引数表から導く(先頭にはサブコマンド名が
 * 並ぶので、その段数 `commandPath.length` を足す)。
 *
 * 数えるのは `--` より前だけ(`maruhi run -- cmd --flag` の後ろは対象外)。
 */
function strayPositionalRejection(
  ctx: ArgCheckContext,
  booleans: BooleanSpellings,
  hint: string | undefined,
  without: readonly string[],
): string | null {
  const declared = namesOfType(ctx.args, "positional").filter((name) => !without.includes(name));
  const expected = declared.length + ctx.commandPath.length;
  const count = positionalCount(ctx);
  if (count <= expected) {
    return null;
  }
  const command = commandLabel(ctx.commandPath);
  const shape =
    declared.length === 0
      ? `${command} は位置引数を取りません`
      : `${command} が取る位置引数は ${declared.join(" ")} だけです`;
  // boolean の助言は boolean を書いた実行にだけ添える(素の打ち間違いに付けると、
  // コマンドラインに無いオプションを探させることになる)
  const usedBoolean = ctx.tokens.some((token) => isBooleanToken(token, booleans));
  const booleanHint = usedBoolean
    ? "。boolean オプションに値は付けられません — 有効にするなら値なしで指定し、無効にするならオプション自体を外してください"
    : "";
  return strayArgumentsMessage(count - expected, shape, `${booleanHint}${hint ?? ""}`);
}

/**
 * `--` の後ろの引数の拒否。これを読むのは `maruhi run` だけで、他のコマンド
 * では黙って捨てられる(`maruhi push NAME -- value` など)。
 */
function strayRestRejection(ctx: ArgCheckContext, acceptsRest: boolean): string | null {
  const rest = restArguments(ctx.tokens);
  if (acceptsRest || rest.length === 0) {
    return null;
  }
  return strayArgumentsMessage(
    rest.length,
    `${commandLabel(ctx.commandPath)} は \`--\` の後ろの引数を取りません`,
  );
}

/**
 * 全コマンド共通の引数検査。拒否する場合はその理由(表示文)、問題なければ null。
 * 呼ぶのは cli.ts の execute — コマンド本体より前に必ず通る。
 */
export function argsRejection(
  ctx: ArgCheckContext,
  options?: {
    /** 余分な位置引数を拒否するときに添えるコマンド固有の助言。 */
    readonly strayPositionalHint?: string | undefined;
    /** `--` の後ろを読むコマンドか(`maruhi run` だけ)。 */
    readonly acceptsRest?: boolean | undefined;
    /**
     * **この実行では**取らない位置引数(既定は引数表の全 positional)。
     * 操作によって数が変わるコマンド(`config get` は set 専用の optional
     * positional `value` を取らない)が、引数表との差を伝えるために使う。
     */
    readonly withoutPositionals?: readonly string[] | undefined;
  },
): string | null {
  // boolean の綴り集合は 1 回だけ作って各検査へ渡す(トークンごとに引数表を
  // 走査し直さない)
  const booleans = booleanSpellings(ctx.args);
  return (
    inlineValueRejection(ctx, booleans) ??
    booleanLiteralRejection(ctx, booleans) ??
    strayPositionalRejection(
      ctx,
      booleans,
      options?.strayPositionalHint,
      options?.withoutPositionals ?? [],
    ) ??
    strayRestRejection(ctx, options?.acceptsRest === true)
  );
}

/** usage エラーの文面を作るために引く、コマンド名 → 引数表の対応。 */
export type CommandTable = Readonly<Record<string, { readonly args?: ArgTable | undefined }>>;

/** 打たれたコマンドの引数表(解決できなければ undefined)。 */
function invokedArgs(argv: readonly string[], commands: CommandTable): ArgTable | undefined {
  // コマンドの解決は gunshi と同じ「最初の位置引数」で行う(自前の argv 走査を
  // 書かないため、パースは gunshi の parseArgs に任せる)。`--` は跨ぐ:
  // gunshi の resolveCommandTree も getPositionalTokens で全 positional を
  // 見るため、option-terminator の前で打ち切ると解決結果が食い違う
  for (const token of parseArgs([...argv])) {
    // gunshi の getPositionalTokens は falsy な値を落とす(`!!v`)。空文字列を
    // コマンド名として扱うと、`maruhi "" env create …` で解決結果が食い違う
    if (token.kind !== "positional" || token.value === undefined || token.value === "") {
      continue;
    }
    return Object.hasOwn(commands, token.value) ? commands[token.value]?.args : undefined;
  }
  return undefined;
}

// 診断へ返してよい綴り = **maruhi のオプション名の語彙**(英字とハイフンだけ。
// 長さは自分の最長オプション名 `--github-poll-interval` = 20 字を超える余地を
// 残す)。gunshi が名前として受ける範囲より意図的に狭くして、値が
// オプションに化けた形を弾く: `-hunter2` は短縮グループとして 1 文字ずつの
// トークンへ展開され、`--sk_live_ab12` は数字と `_` を含み、
// `-----BEGIN RSA...` は 1 つの長い名前になる(いずれも実測)。
// この語彙を外れた綴りは打ち間違いとして案内せず、伏せる
const OPTION_SPELLING = /^(?:--[A-Za-z][A-Za-z-]{0,30}|-[A-Za-z])$/;
const COMMAND_SPELLING = /^[A-Za-z][A-Za-z-]{0,30}$/;

/** 診断へ出してよい綴りなら表示形、そうでなければ null(= 伏せる)。 */
function echoableSpelling(rawName: string, argv: readonly string[]): string | null {
  if (!OPTION_SPELLING.test(rawName)) {
    return null;
  }
  // 打たれたとおりの綴りが argv にある場合だけ出す。短縮グループの展開で
  // 生まれた 1 文字トークン(`-hunter2` → `-u` `-n` …)は argv に無い =
  // オプションではなく値を書いた形なので、綴りを復元して見せない
  const typedByUser = argv.some((arg) => arg === rawName || arg.startsWith(`${rawName}=`));
  return typedByUser ? displayText(rawName) : null;
}

function stringValue(values: Readonly<Record<string, unknown>>, key: string): string | null {
  const value = values[key];
  return typeof value === "string" ? value : null;
}

/** 打たれた綴り(出してよい形のときだけ)。 */
function typedSpelling(
  values: Readonly<Record<string, unknown>>,
  argv: readonly string[],
): string | null {
  const name = stringValue(values, "name");
  const rawName = stringValue(values, "rawName") ?? (name === null ? null : `--${name}`);
  return rawName === null ? null : echoableSpelling(rawName, argv);
}

/** その名前は、このコマンドの**位置引数**として宣言されているか。 */
function isDeclaredPositional(args: ArgTable | undefined, name: string | null): boolean {
  return (
    name !== null &&
    args !== undefined &&
    Object.hasOwn(args, name) &&
    args[name]?.type === "positional"
  );
}

function unknownOptionMessage(
  values: Readonly<Record<string, unknown>>,
  args: ArgTable | undefined,
  argv: readonly string[],
): string {
  const spelled = typedSpelling(values, argv);
  if (spelled === null) {
    return "不明なオプションです(綴りは表示しません — オプションではなく値を書いた形の可能性があるため)";
  }
  // 位置引数の名前をオプションとして書いた形(`env create dev --environment-id
  // prod`)は strict から見れば未宣言のオプションだが、打ち間違いではなく
  // 「値が黙って捨てられる」形なので専用の案内を出す。環境 ID はチェーン履歴
  // 全体で一意(§6.2)なので、取り違えは永久に焼き付く
  if (isDeclaredPositional(args, stringValue(values, "name"))) {
    return `${spelled} は位置引数です(オプションとしては指定できません)。値は位置引数として並べてください`;
  }
  return `不明なオプションです: ${spelled}`;
}

/**
 * 引数検証エラーの日本語文面。**宣言済みの名前**(引数表由来)だけを埋め込み、
 * 与えられた値(`values.actual` 等)は出さない。文面を持たないコード
 * (customParse・conflict)は null を返して gunshi の文面へ委ねる。
 */
function argsValidationMessage(
  code: string,
  values: Readonly<Record<string, unknown>>,
  args: ArgTable | undefined,
  argv: readonly string[],
): string | null {
  const name = stringValue(values, "name");
  if (code === ArgsValidationErrorKeys.unknownOption) {
    return unknownOptionMessage(values, args, argv);
  }
  if (name === null) {
    return null;
  }
  if (code === ArgsValidationErrorKeys.requiredPositional) {
    return `位置引数 ${name} を指定してください`;
  }
  if (code === ArgsValidationErrorKeys.requiredOption) {
    return `オプション --${name} を指定してください`;
  }
  const expected = stringValue(values, "expected");
  if (code === ArgsValidationErrorKeys.invalidType && expected !== null) {
    return `オプション --${name} の値が ${expected} として読めません`;
  }
  const choices = stringValue(values, "choices");
  if (code === ArgsValidationErrorKeys.invalidChoice && choices !== null) {
    return `オプション --${name} は次のいずれかを指定してください: ${choices}`;
  }
  return null;
}

function validationMessage(
  error: unknown,
  args: ArgTable | undefined,
  argv: readonly string[],
): string {
  if (isCommandNotFoundError(error)) {
    const spelled = COMMAND_SPELLING.test(error.commandName)
      ? `: ${displayText(error.commandName)}`
      : "(綴りは表示しません — コマンド名ではなく値を書いた形の可能性があるため)";
    return `不明なコマンドです${spelled}`;
  }
  if (isArgsValidationError(error) && error.code !== undefined) {
    const message = argsValidationMessage(error.code, error.values, args, argv);
    if (message !== null) {
      return message;
    }
  }
  return error instanceof Error ? error.message : String(error);
}

/**
 * gunshi が投げた usage エラー(strict の未宣言オプション検査を含む)を
 * 表示文の並びにする。gunshi 自身の描画は止めてある(cli.ts の
 * `renderValidationErrors: null` / `renderHeader: null`)ので、診断はすべて
 * この経路から stderr へ出る。
 *
 * AggregateError の `message` は先頭 1 件ぶんしか持たない(引数解決の失敗では
 * 空文字列になる)ため、内訳を 1 件ずつ返す。
 */
export function usageErrorMessages(
  error: unknown,
  argv: readonly string[],
  commands: CommandTable,
): readonly string[] {
  if (!(error instanceof AggregateError) || error.errors.length === 0) {
    return [
      error instanceof Error && error.message !== "" ? error.message : "引数を解釈できません",
    ];
  }
  const args = invokedArgs(argv, commands);
  // コマンド名を間違えた実行では、オプションは**エントリコマンドの**引数表と
  // 突き合わされるため、正しく綴られたオプションまで不明として並ぶ
  // (`maruhi pul --show` → `--show` も不明扱い)。誤りはコマンド名の方なので、
  // 綴りの合っているオプションを探させない
  const commandNotFound = error.errors.some((inner: unknown) => isCommandNotFoundError(inner));
  const messages = error.errors
    .filter(
      (inner: unknown) =>
        !commandNotFound ||
        !isArgsValidationError(inner) ||
        inner.code !== ArgsValidationErrorKeys.unknownOption,
    )
    .map((inner: unknown) => validationMessage(inner, args, argv));
  // 伏せ字の文面は同じ形に潰れるので重複を畳む(`-hunter2` は 6 トークンに割れる)
  return [...new Set(messages)];
}
