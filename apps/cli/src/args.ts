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

import { ArgsValidationErrorKeys, isArgsValidationError, parseArgs } from "gunshi";

import { displayText } from "./display.ts";

/** 引数表の 1 エントリ(判定に使う部分だけ)。 */
interface ArgSchemaShape {
  readonly type?: string | undefined;
}

/** gunshi の引数表(`ctx.args`)。宣言済みオプションと位置引数の完全な表。 */
export type ArgTable = Readonly<Record<string, ArgSchemaShape>>;

/** gunshi の引数トークン(`ctx.tokens`)。打たれたとおりの並び。 */
export interface ArgTokenShape {
  readonly kind: string;
  readonly name?: string | undefined;
  readonly rawName?: string | undefined;
  readonly inlineValue?: boolean | undefined;
}

/**
 * 検査に必要な CommandContext の部分。コマンドごとに型の違う `values` を
 * 含めないので、1 つの検査を全コマンドへ適用できる。
 */
export interface ArgCheckContext {
  readonly args: ArgTable;
  readonly tokens: readonly ArgTokenShape[];
  readonly positionals: readonly string[];
  readonly rest: readonly string[];
  readonly commandPath: readonly string[];
}

/** 打たれたとおりの綴りで返す(`-x` を `--x` と書き換えて出さない)。 */
function typedName(token: ArgTokenShape): string {
  return displayText(token.rawName ?? `--${token.name ?? ""}`);
}

function namesOfType(args: ArgTable, type: string): readonly string[] {
  return Object.entries(args)
    .filter(([, schema]) => schema.type === type)
    .map(([name]) => name);
}

/**
 * boolean オプションへの値の指定(`--new-epoch=false`)の拒否。gunshi は値を
 * 読まずにフラグを true にするため、放置すると書いたことと逆の結果になる
 * (チェーンは append-only なので取り消せない)。
 */
function inlineValueRejection(ctx: ArgCheckContext): string | null {
  // Set で引く: `args["constructor"]` のようなプロトタイプ由来の名前を
  // 宣言済み boolean と取り違えない
  const booleans = new Set(namesOfType(ctx.args, "boolean"));
  for (const token of ctx.tokens) {
    if (token.kind !== "option" || token.name === undefined || token.inlineValue !== true) {
      continue;
    }
    if (!booleans.has(token.name)) {
      continue;
    }
    const typed = typedName(token);
    return `${typed} は値を取りません(指定した値は無視され、フラグは有効として扱われます)。有効にするなら値なしで ${typed} と書き、無効にするならオプション自体を外してください`;
  }
  return null;
}

/**
 * 余分な引数の共通文面。**中身は決して出さない**(個数と形だけを言う)。
 *
 * 拒否した引数は任意のユーザー入力であり、平文の値が混ざりうる —
 * `maruhi push API_KEY "$SECRET"`(値は stdin から読むので、この書き方は
 * 余分な引数になる)がその形。診断は CI やエージェントのログに残るため、
 * 打ち間違いを教えるために平文をもう一度書き出す取引はしない
 * (CLAUDE.md: 平文値・鍵素材をログ・エラーメッセージに出力しない)。
 */
export function strayArgumentsMessage(count: number, shape: string, suffix = ""): string {
  return `余分な引数です(${count} 個。中身は表示しません — 平文の値が混ざりうるため)。${shape}${suffix}`;
}

/**
 * 余分な位置引数の拒否。boolean は**空白区切りの値を読まない**ため、
 * `--show false` は「フラグ有効 + 位置引数 "false"」になり、無効にした
 * つもりが値の表示になる。想定数は引数表から導く(`ctx.positionals` の
 * 先頭にはサブコマンド名が並ぶので、その段数 `commandPath.length` を足す)。
 *
 * `--` の後ろ(`maruhi run -- cmd --flag`)は positional トークンとして
 * `ctx.rest` にだけ入り、`ctx.positionals` には現れないので影響しない。
 */
function strayPositionalRejection(ctx: ArgCheckContext, hint: string | undefined): string | null {
  const declared = namesOfType(ctx.args, "positional");
  const expected = declared.length + ctx.commandPath.length;
  if (ctx.positionals.length <= expected) {
    return null;
  }
  const command = ["maruhi", ...ctx.commandPath].join(" ");
  const shape =
    declared.length === 0
      ? `${command} は位置引数を取りません`
      : `${command} が取る位置引数は ${declared.join(" ")} だけです`;
  // boolean の助言は boolean を書いた実行にだけ添える(素の打ち間違いに付けると、
  // コマンドラインに無いオプションを探させることになる)
  const booleans = new Set(namesOfType(ctx.args, "boolean"));
  const usedBoolean = ctx.tokens.some(
    (token) => token.kind === "option" && token.name !== undefined && booleans.has(token.name),
  );
  const booleanHint = usedBoolean
    ? "。boolean オプションに値は付けられません — 有効にするなら値なしで指定し、無効にするならオプション自体を外してください"
    : "";
  return strayArgumentsMessage(
    ctx.positionals.length - expected,
    shape,
    `${booleanHint}${hint ?? ""}`,
  );
}

/**
 * `--` の後ろの引数(`ctx.rest`)の拒否。これを読むのは `maruhi run` だけで、
 * 他のコマンドでは黙って捨てられる(`maruhi push NAME -- value` など)。
 */
function strayRestRejection(ctx: ArgCheckContext, acceptsRest: boolean): string | null {
  if (acceptsRest || ctx.rest.length === 0) {
    return null;
  }
  const command = ["maruhi", ...ctx.commandPath].join(" ");
  return strayArgumentsMessage(ctx.rest.length, `${command} は \`--\` の後ろの引数を取りません`);
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
  },
): string | null {
  return (
    inlineValueRejection(ctx) ??
    strayPositionalRejection(ctx, options?.strayPositionalHint) ??
    strayRestRejection(ctx, options?.acceptsRest === true)
  );
}

/** usage エラーの文面を作るために引く、コマンド名 → 引数表の対応。 */
export type CommandTable = Readonly<Record<string, { readonly args?: ArgTable | undefined }>>;

/** 打たれたコマンドの引数表(解決できなければ undefined)。 */
function invokedArgs(argv: readonly string[], commands: CommandTable): ArgTable | undefined {
  // コマンドの解決は gunshi と同じ「最初の位置引数」で行う(自前の argv
  // 走査を書かないため、パースは gunshi の parseArgs に任せる)
  for (const token of parseArgs([...argv])) {
    if (token.kind === "option-terminator") {
      return undefined;
    }
    if (token.kind !== "positional" || token.value === undefined) {
      continue;
    }
    return Object.hasOwn(commands, token.value) ? commands[token.value]?.args : undefined;
  }
  return undefined;
}

function unknownOptionMessage(
  values: Readonly<Record<string, unknown>>,
  args: ArgTable | undefined,
): string {
  const name = values["name"];
  const rawName = values["rawName"];
  const typed = displayText(
    typeof rawName === "string" ? rawName : `--${typeof name === "string" ? name : ""}`,
  );
  // 位置引数の名前をオプションとして書いた形(`env create dev --environment-id
  // prod`)は strict から見れば未宣言のオプションだが、打ち間違いではなく
  // 「値が黙って捨てられる」形なので専用の案内を出す。環境 ID はチェーン履歴
  // 全体で一意(§6.2)なので、取り違えは永久に焼き付く
  if (
    typeof name === "string" &&
    args !== undefined &&
    Object.hasOwn(args, name) &&
    args[name]?.type === "positional"
  ) {
    return `${typed} は位置引数です(オプションとしては指定できません)。値は位置引数として並べてください`;
  }
  return `不明なオプションです: ${typed}`;
}

/**
 * gunshi が投げた usage エラー(strict の未宣言オプション検査を含む)を
 * 表示文の並びにする。gunshi 自身の描画は止めてある(cli.ts の
 * `renderValidationErrors: null`)ので、診断はすべてこの経路から stderr へ出る。
 *
 * AggregateError の `message` は先頭 1 件ぶんしか持たない(引数解決の失敗では
 * 空文字列になる)ため、内訳を 1 件ずつ返す。
 */
export function usageErrorMessages(
  error: unknown,
  argv: readonly string[],
  commands: CommandTable,
): readonly string[] {
  if (error instanceof AggregateError && error.errors.length > 0) {
    const args = invokedArgs(argv, commands);
    return error.errors.map((inner: unknown) =>
      isArgsValidationError(inner) && inner.code === ArgsValidationErrorKeys.unknownOption
        ? unknownOptionMessage(inner.values, args)
        : inner instanceof Error
          ? inner.message
          : String(inner),
    );
  }
  if (error instanceof Error && error.message !== "") {
    return [error.message];
  }
  return ["引数を解釈できません"];
}
