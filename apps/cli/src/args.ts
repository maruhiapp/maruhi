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
// 診断の規律: **打たれた語は診断に出さない**。拒否されるのは「値をオプション /
// 位置引数として書いてしまった」形でもありうるので、平文が stderr →
// CI・エージェントのログへ流れる経路を作らない(CLAUDE.md: 平文値・鍵素材を
// ログ・エラーメッセージに出力しない)。
//
// 出してよいのは**こちらの語彙**だけ: 引数表由来の名前(宣言済みのオプション /
// 位置引数 / 期待する型)と、サブコマンド名。打ち間違いの案内は「打たれた綴りを
// 返す」のではなく、**宣言名から編集距離で候補を出す**(suggestionText)。
// 打たれた綴りをそのまま出すのは、それが宣言名と一致した場合だけ
// (= もはやこちらの語彙)。

import {
  ArgsValidationErrorKeys,
  isArgsValidationError,
  isCommandNotFoundError,
  parseArgs,
} from "gunshi";

import { displayText } from "./display.ts";

/** ブランド名 = 表示に使うコマンド名(`mh` で起動しても表記は maruhi)。 */
const CLI_NAME = "maruhi";

/** gunshi の否定形の接頭辞(`negatable: true` の boolean に付く)。 */
const NEGATION_PREFIX = "no-";

/** gunshi が全コマンドへ混ぜるオプション(引数表には現れないが受け付ける)。 */
const GLOBAL_OPTIONS = ["--help", "--version"] as const;

/** 引数表の 1 エントリ(判定に使う部分だけ)。 */
interface ArgSchemaShape {
  readonly type?: string | undefined;
  readonly short?: string | undefined;
  readonly negatable?: boolean | undefined;
  /** usage に出さない宣言(テスト用・内部向け)。候補にも出さない。 */
  readonly hidden?: boolean | undefined;
}

/** The command's full argument table (`ctx.args`): declared options and positionals. */
export type ArgTable = Readonly<Record<string, ArgSchemaShape>>;

/** One parsed argument token (`ctx.tokens`), in the order it was typed. */
export interface ArgTokenShape {
  readonly kind: string;
  readonly name?: string | undefined;
  readonly rawName?: string | undefined;
  readonly value?: string | undefined;
  readonly inlineValue?: boolean | undefined;
}

/**
 * The slice of gunshi's CommandContext the checks need.
 *
 * コマンドごとに型の違う `values` を含めないので、1 つの検査を全コマンドへ
 * 適用できる。
 *
 * `--` の後ろは **`ctx.rest` を使わず**トークンから組み直す(下記
 * restArguments を参照 — 空文字列の引数が rest から落ちて positionals へ
 * 紛れ込むため)。位置引数の数もその紛れ込みを引いて数える。
 */
export interface ArgCheckContext {
  readonly args: ArgTable;
  readonly tokens: readonly ArgTokenShape[];
  readonly positionals: readonly string[];
  /** 引数表を通した値(オプションの空の値は undefined へ落ちる)。 */
  readonly values: Readonly<Record<string, unknown>>;
  /** 明示的に書かれたか(「未指定」と「空指定」の区別はここにしか無い)。 */
  readonly explicit: Readonly<Record<string, boolean>>;
  readonly commandPath: readonly string[];
}

/** Renders an option token as it was typed (never rewrites `-x` into `--x`). */
export function typedName(token: ArgTokenShape): string {
  return displayText(token.rawName ?? `--${token.name ?? ""}`);
}

/**
 * The arguments after `--` (what `maruhi run` passes to the child process).
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
  // 空の位置引数は数に入れない: gunshi はコマンド解決で falsy な値を読み飛ばす
  // (`maruhi "" pull` の "" は commandPath に入らない)一方 `ctx.positionals`
  // には残るので、そのまま数えると全体が 1 つずれて無関係な引数を責める。
  // `--` の後ろから紛れ込んだ空文字列も同じ扱いでよい
  return ctx.positionals.filter((value) => value !== "").length;
}

function namesOfType(args: ArgTable, type: string): readonly string[] {
  return Object.entries(args)
    .filter(([, schema]) => schema.type === type)
    .map(([name]) => name);
}

/** boolean オプション 1 つ(打たれた綴りから逆引きするための最小の情報)。 */
interface BooleanOption {
  /** 宣言名(否定形 `--no-<name>` の組み立てに使う)。 */
  readonly name: string;
  /** `negatable` 宣言があるか(= 無効にする書き方が存在するか)。 */
  readonly negatable: boolean;
}

/**
 * boolean として書かれうる綴り → その宣言。長い名前と短縮形を**別々に**持つ:
 * 1 つの表に混ぜると、ある boolean の短縮形と同じ名前を持つ別のオプション
 * (例: 長い名前が `h` の string)を boolean と取り違える。
 */
function booleanSpellings(args: ArgTable): {
  readonly long: ReadonlyMap<string, BooleanOption>;
  readonly short: ReadonlyMap<string, BooleanOption>;
} {
  const long = new Map<string, BooleanOption>();
  const short = new Map<string, BooleanOption>();
  for (const [name, schema] of Object.entries(args)) {
    if (schema.type !== "boolean") {
      continue;
    }
    const negatable = schema.negatable === true;
    const option: BooleanOption = { name, negatable };
    long.set(name, option);
    if (negatable) {
      // 否定形も同じオプションの綴り。入れ忘れると `--no-show=false` /
      // `--no-new-epoch off` が boolean の検査を素通りする(gunshi はトークン名を
      // `no-<name>` のまま渡す)
      long.set(`${NEGATION_PREFIX}${name}`, option);
    }
    if (schema.short !== undefined) {
      short.set(schema.short, option);
    }
  }
  return { long, short };
}

/**
 * Resolves the declared argument name a token spells (long, short, or the
 * `--no-` negation), or undefined when the spelling is not declared.
 */
export function declaredOptionName(token: ArgTokenShape, args: ArgTable): string | undefined {
  if (token.kind !== "option" || token.name === undefined) {
    return undefined;
  }
  if (token.rawName?.startsWith("--") === false) {
    const short = token.name;
    return Object.entries(args).find(([, schema]) => schema.short === short)?.[0];
  }
  if (Object.hasOwn(args, token.name)) {
    return token.name;
  }
  // `--no-x` は `x` の否定形(negatable 宣言のときだけ)
  const bare = token.name.startsWith(NEGATION_PREFIX)
    ? token.name.slice(NEGATION_PREFIX.length)
    : null;
  return bare !== null && Object.hasOwn(args, bare) && args[bare]?.negatable === true
    ? bare
    : undefined;
}

type BooleanSpellings = ReturnType<typeof booleanSpellings>;

/** そのトークンが指す boolean オプション(短縮形は綴りで見分ける)。 */
function booleanOptionOf(
  token: ArgTokenShape,
  booleans: BooleanSpellings,
): BooleanOption | undefined {
  if (token.kind !== "option" || token.name === undefined) {
    return undefined;
  }
  return token.rawName?.startsWith("--") === false
    ? booleans.short.get(token.name)
    : booleans.long.get(token.name);
}

// 「フラグの値のつもりで書いた」と読める語。boolean の直後に置かれたこれらは
// 位置引数ではなく値の指定と判断する。網羅は原理的に無理なので、**無効に
// する正しい書き方**(`negatable` による `--no-<name>`)を必ず案内へ添える
function isBooleanLiteral(token: ArgTokenShape): boolean {
  return BOOLEAN_LITERALS.has((token.value ?? "").toLowerCase());
}

const BOOLEAN_LITERALS = new Set([
  "true",
  "false",
  "t",
  "f",
  "yes",
  "no",
  "y",
  "n",
  "on",
  "off",
  "0",
  "1",
  "enable",
  "disable",
  "enabled",
  "disabled",
]);

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
function booleanTakesNoValue(token: ArgTokenShape, option: BooleanOption): string {
  const typed = typedName(token);
  // 有効 / 無効の**両方の書き方**を示す。打たれたのが否定形(`--no-x`)でも
  // 「有効にするなら --no-x」と言わないよう、宣言名から組み立てる
  const how = option.negatable
    ? `有効にするなら --${option.name}、無効にするなら --${NEGATION_PREFIX}${option.name} と、いずれも値なしで書いてください`
    : `有効にするなら値なしで --${option.name} と書き、無効にするならオプション自体を外してください`;
  return `${typed} は値を取りません(指定した値は無視され、フラグは有効として扱われます)。${how}`;
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
    const flag = token.kind === "positional" && isBooleanLiteral(token) ? previous : undefined;
    const option = flag === undefined ? undefined : booleanOptionOf(flag, booleans);
    if (flag !== undefined && option !== undefined) {
      // 環境 ID が本当に `1` / `n` のような語である可能性は残る。並べ替えれば
      // 通ることを示して手詰まりにしない(位置引数を取るコマンドに限る —
      // 取らないコマンドで勧めると、そのとおり直しても余分な引数で落ちる)
      const escape =
        namesOfType(ctx.args, "positional").length > 0
          ? "。その語が本当に位置引数なら、オプションより前に書いてください"
          : "";
      return `${booleanTakesNoValue(flag, option)}${escape}`;
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
    const option = named === undefined ? undefined : booleanOptionOf(named, booleans);
    if (token.inlineValue !== true || named === undefined || option === undefined) {
      continue;
    }
    return booleanTakesNoValue(named, option);
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
  rest: readonly string[],
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
  const usedBoolean = ctx.tokens.some((token) => booleanOptionOf(token, booleans) !== undefined);
  const booleanHint = usedBoolean
    ? "。boolean オプションに値は付けられません — 有効にするなら値なしで指定し、無効にするならオプション自体を外してください"
    : "";
  return strayArgumentsMessage(count - expected, shape, `${booleanHint}${hint ?? ""}`);
}

/**
 * 明示されたのに**値が空**のオプション(`--env ""` / `--env=`)の拒否。
 *
 * gunshi の string / number は `token.value || default` で解決するため、空の値は
 * 「未指定」に潰れて既定へフォールバックする。`maruhi push API_KEY --env "$ENV"`
 * で ENV が未設定なら、書き込みは**既定環境**へ入る(取り消せない)。
 * 「未指定」と「空指定」の区別は `ctx.explicit` にしか無い。
 */
function emptyOptionValueRejection(ctx: ArgCheckContext): string | null {
  // 判定は**打たれたトークン**で行う。`ctx.values` が undefined かどうかで
  // 見ると、そのオプションに `default` を付けた瞬間に検知が消える
  // (空の値が既定へ解決されるため)= 塞いだはずの穴が黙って開く
  for (const [index, token] of ctx.tokens.entries()) {
    if (token.kind === "option-terminator") {
      break;
    }
    const declared = valueTakingOption(token, ctx.args);
    if (declared !== undefined && hasEmptyValue(token, ctx.tokens[index + 1])) {
      return `オプション --${declared} の値が空です(空の値は「未指定」と区別できないため受け付けません)`;
    }
  }
  return null;
}

/** そのトークンが指す「値を取る」オプションの宣言名(boolean / 位置引数は除く)。 */
function valueTakingOption(token: ArgTokenShape, args: ArgTable): string | undefined {
  const declared = declaredOptionName(token, args);
  const type = declared === undefined ? undefined : args[declared]?.type;
  return type === undefined || type === "positional" || type === "boolean" ? undefined : declared;
}

/** `--env=` はインライン値が空、`--env ""` は次の位置引数トークンが空。 */
function hasEmptyValue(token: ArgTokenShape, next: ArgTokenShape | undefined): boolean {
  return token.inlineValue === true
    ? (token.value ?? "") === ""
    : next?.kind === "positional" && next.value === "";
}

/**
 * 空の位置引数(`maruhi config set server ""`)の拒否。
 *
 * 位置引数は空文字列のまま束縛される(オプションと違って undefined へ落ちない)
 * ため、`config set defaultProject "$PROJ"` の未設定形が既存の設定を空で
 * 上書きして成功を報告していた。
 */
function emptyPositionalRejection(
  ctx: ArgCheckContext,
  rest: readonly string[],
  without: readonly string[],
): string | null {
  for (const name of namesOfType(ctx.args, "positional")) {
    if (without.includes(name)) {
      // この実行では取らない位置引数(`config get` の `value`)を名指ししない
      continue;
    }
    const value = ctx.values[name];
    // 空白だけの値も空として扱う(`config set defaultProject "$PROJ"` の
    // 未設定形は `""`、`" "` のどちらにもなりうる)
    if (typeof value === "string" && value.trim() === "") {
      return `位置引数 ${name} が空です(空白だけの値も受け付けません)`;
    }
  }
  // どの宣言にも束縛されなかった空の引数(`maruhi "" pull` の "")。
  // gunshi は読み飛ばすので、黙って落とさないためにここで拾う
  const leakedFromRest = rest.filter((value) => value.trim() === "").length;
  const empties = ctx.positionals.filter((value) => value.trim() === "").length;
  return empties > leakedFromRest ? "空の引数があります(空の値は受け付けません)" : null;
}

/**
 * コマンド名が `--` の**後ろ**にある実行の拒否。gunshi は `--` を跨いで
 * コマンドを解決する(`getPositionalTokens` は全 positional を見る)ため、
 * `maruhi -- run printenv` は run として解決され、`--` の後ろの先頭
 * (= コマンド名そのもの)が実行対象として渡ってしまう。
 */
function commandBeforeTerminatorRejection(
  ctx: ArgCheckContext,
  rest: readonly string[],
): string | null {
  if (ctx.commandPath.length === 0 || rest.length === 0) {
    return null;
  }
  return positionalCount(ctx) < ctx.commandPath.length
    ? "コマンド名は `--` より前に書いてください(`--` の後ろはそのまま渡す引数です)"
    : null;
}

/**
 * `--` の後ろの引数の拒否。これを読むのは `maruhi run` だけで、他のコマンド
 * では黙って捨てられる(`maruhi push NAME -- value` など)。
 */
function strayRestRejection(
  rest: readonly string[],
  ctx: ArgCheckContext,
  acceptsRest: boolean,
  hint: string | undefined,
) {
  if (acceptsRest || rest.length === 0) {
    return null;
  }
  // 中身を伏せる以上、直し方(コマンド固有の助言)は位置引数側と同じく必ず添える
  return strayArgumentsMessage(
    rest.length,
    `${commandLabel(ctx.commandPath)} は \`--\` の後ろの引数を取りません`,
    hint ?? "",
  );
}

/**
 * `--` の後ろに実行対象が要るコマンド(`maruhi run`)で、それが無い場合の拒否。
 * 空文字列は実行できない(`maruhi run -- "$CMD"` の未設定形)ので「引数が
 * 1 つある」ことと「実行対象がある」ことを区別する。
 *
 * 共通検査の**中**に置く: コマンド側で先に判定すると、余分な位置引数のような
 * より具体的な誤り(`maruhi run stray -- "" cmd`)がこの文面に潰される。
 */
function missingRestRejection(
  rest: readonly string[],
  required: string | undefined,
): string | null {
  if (required === undefined) {
    return null;
  }
  // 空白だけのコマンド名も実行できない(`maruhi run -- "$CMD"` の未設定形)
  return rest.length === 0 || (rest[0] ?? "").trim() === "" ? required : null;
}

/** How one command tunes the shared argument checks. */
export interface ArgsCheckOptions {
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
  /**
   * `--` の後ろに実行対象が必須なコマンド(`maruhi run`)の案内文。渡すと
   * 「実行対象が無い」実行を共通検査の中で(= より具体的な誤りの後に)落とす。
   */
  readonly restRequired?: string | undefined;
  /**
   * コマンド固有の拒否(env の操作別オプションの適用可否)。**共通検査より
   * 先**に見るが、連鎖の中に置くので「共通検査を飛ばす」ことはできない。
   */
  readonly commandRejection?: string | null | undefined;
  /** `--` の後ろ(コマンド側で組み済みなら渡す — 2 度組まない)。 */
  readonly rest?: readonly string[] | undefined;
}

/**
 * Checks how the arguments were written; returns the rejection message to show,
 * or null when the invocation is well-formed.
 *
 * 呼ぶのは cli.ts の execute — コマンド本体より前に必ず通る。
 */
export function argsRejection(ctx: ArgCheckContext, options?: ArgsCheckOptions): string | null {
  // boolean の綴り集合は 1 回だけ作って各検査へ渡す(トークンごとに引数表を
  // 走査し直さない)
  const booleans = booleanSpellings(ctx.args);
  // `--` の後ろの組み直しも 1 回だけ(位置引数の数え上げと 2 つの検査で使う)
  const rest = options?.rest ?? restArguments(ctx.tokens);
  return (
    // 適用できないオプションは、綴りの助言より先に言う(そのとおり直しても
    // 次の実行でまた落ちるため)
    // 並びは「実行の形そのもの → その操作で使えるか → 綴り」の順。
    // 構造的な誤り(コマンド名の位置・空の値・`--` の後ろ)を先に言わないと、
    // 操作別の指摘を直した次の実行でまた落ちる
    commandBeforeTerminatorRejection(ctx, rest) ??
    emptyOptionValueRejection(ctx) ??
    strayRestRejection(rest, ctx, options?.acceptsRest === true, options?.strayPositionalHint) ??
    emptyPositionalRejection(ctx, rest, options?.withoutPositionals ?? []) ??
    options?.commandRejection ??
    inlineValueRejection(ctx, booleans) ??
    booleanLiteralRejection(ctx, booleans) ??
    strayPositionalRejection(
      ctx,
      rest,
      booleans,
      options?.strayPositionalHint,
      options?.withoutPositionals ?? [],
    ) ??
    missingRestRejection(rest, options?.restRequired)
  );
}

/** Command name → argument table, used to word usage errors. */
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

/**
 * 打ち間違いの候補提示に使う編集距離。名前は高々数十字なので素直な DP。
 */
function editDistance(a: string, b: string): number {
  const row = Array.from({ length: b.length + 1 }, (_, index) => index);
  for (let i = 1; i <= a.length; i += 1) {
    let diagonal = row[0] ?? 0;
    row[0] = i;
    for (let j = 1; j <= b.length; j += 1) {
      const above = row[j] ?? 0;
      row[j] = Math.min(
        above + 1,
        (row[j - 1] ?? 0) + 1,
        diagonal + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
      diagonal = above;
    }
  }
  return row[b.length] ?? 0;
}

/**
 * 打ち間違いとして案内する編集距離の上限。3 まで許すと `--prj` に `--env` を、
 * `bogus` に `login` を勧めるような**見当違いの候補**が出るので 2 に絞り、
 * 外れた場合は候補一覧を出す。
 */
const SUGGESTION_DISTANCE = 2;

/** 候補のうち最も近いもの(遠ければ null)。 */
function nearest(typed: string, candidates: readonly string[]): string | null {
  let best: string | null = null;
  let bestDistance = SUGGESTION_DISTANCE + 1;
  for (const candidate of candidates) {
    const distance = editDistance(typed, candidate);
    if (distance < bestDistance) {
      best = candidate;
      bestDistance = distance;
    }
  }
  return bestDistance <= SUGGESTION_DISTANCE ? best : null;
}

/**
 * 「候補」の文面。**打たれた綴りは出さず**、こちらの語彙(宣言名 / コマンド名)
 * だけで案内する — 拒否された綴りは値でもありうるため(モジュール冒頭の規律)。
 */
function suggestionText(
  typed: string | null,
  candidates: readonly string[],
  label: string,
): string {
  const guess = typed === null ? null : nearest(typed, candidates);
  if (guess !== null) {
    return `(${guess} のことですか?)`;
  }
  return candidates.length === 0 ? "" : `(${label}: ${candidates.toSorted().join(" ")})`;
}

/**
 * 隠しオプション(`hidden: true`)か。gunshi の usage は出さないので、
 * 打ち間違いの案内でも出さない(内部向けの綴りを広めない)。
 */
function isHiddenOption(candidate: string, args: ArgTable | undefined): boolean {
  if (args === undefined || !candidate.startsWith("--")) {
    return false;
  }
  const name = candidate.slice(2);
  const bare = name.startsWith(NEGATION_PREFIX) ? name.slice(NEGATION_PREFIX.length) : name;
  return (Object.hasOwn(args, bare) ? args[bare]?.hidden : undefined) === true;
}

/**
 * このコマンドが取るオプションの綴り。gunshi がエラーに載せた候補
 * (`values.candidates`)を優先する — こちらの引数表には実行時に混ぜられる
 * グローバル(`--help` / `--version`)も否定形(`--no-x`)も現れないため。
 */
function optionCandidates(
  values: Readonly<Record<string, unknown>>,
  args: ArgTable | undefined,
): readonly string[] {
  const candidates = values["candidates"];
  if (Array.isArray(candidates) && candidates.length > 0) {
    return candidates
      .filter((candidate): candidate is string => typeof candidate === "string")
      .filter((candidate) => !isHiddenOption(candidate, args));
  }
  // 短縮形の未宣言オプションでは gunshi が候補を空で渡す(長い綴りの候補しか
  // 持たない)。その場合は引数表から組む — 実行時に混ぜられるグローバルと
  // 否定形は引数表に無いので、こちらで補う(無いと、案内した `--no-x` が
  // 一覧に出てこない)
  if (args === undefined) {
    return GLOBAL_OPTIONS;
  }
  const declared = Object.entries(args).flatMap(([name, schema]) =>
    schema.type === "positional" || schema.hidden === true
      ? []
      : schema.negatable === true
        ? [`--${name}`, `--${NEGATION_PREFIX}${name}`]
        : [`--${name}`],
  );
  return [...declared, ...GLOBAL_OPTIONS];
}

function stringValue(values: Readonly<Record<string, unknown>>, key: string): string | null {
  const value = values[key];
  return typeof value === "string" ? value : null;
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
): string {
  const name = stringValue(values, "name");
  // 位置引数の名前をオプションとして書いた形(`env create dev --environment-id
  // prod`)は strict から見れば未宣言のオプションだが、打ち間違いではなく
  // 「値が黙って捨てられる」形なので専用の案内を出す。ここで出す名前は
  // **引数表由来**(= こちらの語彙)なので伏せる必要がない。環境 ID は
  // チェーン履歴全体で一意(§6.2)なので、取り違えは永久に焼き付く
  if (isDeclaredPositional(args, name)) {
    return `--${name} は位置引数です(オプションとしては指定できません)。値は位置引数として並べてください`;
  }
  // 候補提示は長い綴りのときだけ(短縮形 `-q` を `--q` に見立てて比べると、
  // 無関係な長いオプションが「のことですか?」で出てくる)
  const rawName = stringValue(values, "rawName");
  const typed = rawName !== null && rawName.startsWith("--") ? rawName : null;
  return `不明なオプションです${suggestionText(typed, optionCandidates(values, args), "このコマンドが取るオプション")}`;
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
): string | null {
  const name = stringValue(values, "name");
  if (code === ArgsValidationErrorKeys.unknownOption) {
    return unknownOptionMessage(values, args);
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
  commands: CommandTable,
): string {
  if (isCommandNotFoundError(error)) {
    // エントリコマンドは自分自身の名前でも登録されている(commandLabel と同じ
    // 事情)。`maruhi maruhi` をサブコマンドとして勧めない
    const candidates = (
      error.candidates.length > 0 ? error.candidates : Object.keys(commands)
    ).filter((candidate) => candidate !== CLI_NAME);
    return `不明なコマンドです${suggestionText(error.commandName, candidates, "使えるコマンド")}`;
  }
  if (isArgsValidationError(error) && error.code !== undefined) {
    const message = argsValidationMessage(error.code, error.values, args);
    if (message !== null) {
      return message;
    }
  }
  return error instanceof Error ? error.message : String(error);
}

/**
 * Turns the usage error gunshi threw (including strict's unknown-option check)
 * into the lines to show.
 *
 * gunshi 自身の描画は止めてある(cli.ts の `renderValidationErrors: null` /
 * `renderHeader: null`)ので、診断はすべてこの経路から stderr へ出る。
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
    // 検証エラー以外(パーサ内部の例外など)は文面がこちらの語彙ではない —
    // JS の内部メッセージを `maruhi:` の顔で出さない
    return ["引数を解釈できません"];
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
    .map((inner: unknown) => validationMessage(inner, args, commands));
  // 伏せ字の文面は同じ形に潰れるので重複を畳む(`-hunter2` は 6 トークンに割れる)
  return [...new Set(messages)];
}
