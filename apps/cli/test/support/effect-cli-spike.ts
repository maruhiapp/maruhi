// effect/unstable/cli への移行スパイク(pull / run / env create の 3 コマンド)。
//
// 目的は「gunshi を effect/unstable/cli に替えたとき、maruhi の**規律**が
// そのまま乗るか」を実測すること。規律とは:
//
// 1. 打たれた語・値を診断に出さない(平文が stderr → CI / エージェントの
//    ログへ流れる経路を作らない。CLAUDE.md のディスクレス不変条件)
// 2. stdout はコマンドの出力だけ(ヘルプ・診断は stderr)
// 3. 書き方の誤り = exit 2、実行の失敗 = exit 1
// 4. 値を扱う前に落とす(復号された平文をそもそも作らない)
//
// 本番の src/cli.ts は触っていない(gunshi のまま)。ここは測定用の実装で、
// 採用が決まったら src へ昇格させる。オペレーション本体(pullVariables /
// runOp / envCreateOp)は引数層の測定に関係しないため、呼び出しの記録に
// 置き換えてある — 検査対象は**引数層と診断**であって通信・復号ではない。
//
// 実測の結論は docs/notes/cli-parser-alternatives.md §6 に書いた。

import { Cause, Console, Effect, Exit, FileSystem, Layer, Path, Stdio, Terminal } from "effect";
import { Argument, CliError, Command, Flag } from "effect/unstable/cli";
import { ChildProcessSpawner } from "effect/unstable/process";

import { ensureValueDisplayAllowed } from "../../src/agent.ts";
import type { CliError as MaruhiCliError } from "../../src/errors.ts";
import type { AgentProfile } from "../../src/io.ts";
import { RUN_COMMAND_REQUIRED } from "../../src/run.ts";

/** 1 コマンドの宣言(検査は宣言から導く — 手書きの一覧と二重管理にしない)。 */
interface CommandSpec {
  /** 宣言済みオプション名 → 値を取るか(boolean は取らない)。 */
  readonly flags: Readonly<Record<string, "value" | "boolean">>;
  /** 宣言済み位置引数の名前(順序どおり)。 */
  readonly positionals: readonly string[];
  /** `--` の後ろを読むか(`maruhi run` だけ)。 */
  readonly acceptsRest: boolean;
  /** `--` の後ろに実行対象が要る場合の文面。 */
  readonly restRequired?: string | undefined;
  /** 余分な引数を拒否するときに添えるコマンド固有の助言。 */
  readonly strayHint?: string | undefined;
}

const COMMON_FLAGS = { server: "value", project: "value" } as const;

const SPECS: Readonly<Record<string, CommandSpec>> = {
  pull: {
    flags: { ...COMMON_FLAGS, env: "value", show: "boolean" },
    positionals: [],
    acceptsRest: false,
  },
  run: {
    flags: { ...COMMON_FLAGS, env: "value" },
    positionals: [],
    acceptsRest: true,
    restRequired: RUN_COMMAND_REQUIRED,
    strayHint: "。実行するコマンドは `--` の後に並べてください(例: maruhi run -- printenv MY_VAR)",
  },
  "env create": {
    flags: { ...COMMON_FLAGS, name: "value" },
    positionals: ["environment-id"],
    acceptsRest: false,
  },
};

/** 記録された 1 回の実行(引数層が何を解決したか)。 */
export interface SpikeInvocation {
  readonly command: string;
  readonly values: Readonly<Record<string, unknown>>;
  readonly rest?: readonly string[] | undefined;
}

/** スパイク実行の結果。stdout / stderr は行単位で捕捉する。 */
export interface SpikeOutcome {
  readonly exitCode: number;
  readonly stdout: readonly string[];
  readonly stderr: readonly string[];
  readonly invoked: SpikeInvocation | null;
}

/** 実行時に差し替える環境(既定は非エージェント)。 */
export interface SpikeOptions {
  readonly agent?: AgentProfile | undefined;
}

/* -------------------------------------------------------------------------- */
/* コマンド定義                                                                */
/* -------------------------------------------------------------------------- */

const serverFlag = Flag.string("server").pipe(Flag.optional);
const projectFlag = Flag.string("project").pipe(Flag.optional);
const envFlag = Flag.string("env").pipe(Flag.optional);

function makeCommands(record: (invocation: SpikeInvocation) => void, agent: AgentProfile) {
  const pull = Command.make(
    "pull",
    { server: serverFlag, project: projectFlag, env: envFlag, show: Flag.boolean("show") },
    (values) =>
      Effect.gen(function* () {
        // 値の表示拒否(AI エージェント検出)はコマンド入口 = 復号前。
        // src/cli.ts と同じ位置・同じ関数(agent.ts)を使う
        if (values.show) {
          yield* ensureValueDisplayAllowed(agent);
        }
        record({ command: "pull", values });
      }),
  );

  const run = Command.make(
    "run",
    {
      server: serverFlag,
      project: projectFlag,
      env: envFlag,
      // `--` の後ろはここに入る(空文字列も保持される — gunshi の ctx.rest と
      // 違い、restArguments の再構築が要らない)
      rest: Argument.string("command").pipe(Argument.variadic),
    },
    (values) =>
      Effect.sync(() => {
        const { rest, ...flags } = values;
        record({ command: "run", values: flags, rest: rest.map(String) });
      }),
  );

  const envCreate = Command.make(
    "create",
    {
      server: serverFlag,
      project: projectFlag,
      name: Flag.string("name").pipe(Flag.optional),
      environmentId: Argument.string("environment-id"),
    },
    (values) => Effect.sync(() => record({ command: "env create", values })),
  );

  // gunshi は 1 段(サブコマンド + positional の action)しか組めないため、
  // maruhi は create / rotate / diff を**位置引数**にしていた。その結果
  // 1 つの引数表に全操作のフラグが同居し、「その操作に適用されない
  // オプション」の拒否(cli.ts の ENV_ACTION_FLAGS / optionRestrictedTo)を
  // 自前で書く必要があった。effect/unstable/cli は入れ子のサブコマンドを
  // 組めるので、その機構ごと不要になる
  const env = Command.make("env").pipe(Command.withSubcommands([envCreate]));

  return Command.make("maruhi").pipe(Command.withSubcommands([pull, run, env]));
}

/* -------------------------------------------------------------------------- */
/* 事前検査(パーサに任せられない maruhi 固有の規律)                          */
/* -------------------------------------------------------------------------- */

/** 打たれたトークンから宣言名を引く(`--no-show` / `--env=x` を正規化する)。 */
function declaredNameOf(token: string, spec: CommandSpec): string | null {
  if (!token.startsWith("--")) {
    return null;
  }
  const withoutValue = token.slice(2).split("=")[0] ?? "";
  const negated = withoutValue.startsWith("no-") ? withoutValue.slice(3) : withoutValue;
  if (spec.flags[withoutValue] !== undefined) {
    return withoutValue;
  }
  return spec.flags[negated] !== undefined ? negated : null;
}

function isBlank(value: string | undefined): boolean {
  return value === undefined || value.trim() === "";
}

/**
 * `--` の前後に分ける。effect/unstable/cli 自身も `--` を跨いでコマンドを
 * 解決しない(実測)ので、ここは検査のための切り分けだけ。
 */
function splitAtTerminator(argv: readonly string[]): {
  readonly head: readonly string[];
  readonly rest: readonly string[] | null;
} {
  const index = argv.indexOf("--");
  return index === -1
    ? { head: argv, rest: null }
    : { head: argv.slice(0, index), rest: argv.slice(index + 1) };
}

interface HeadScan {
  /** 宣言名 → 打たれた回数(綴りではなく宣言名で数える)。 */
  readonly counts: ReadonlyMap<string, number>;
  /** コマンド名の段を除いた位置引数(打たれた順)。 */
  readonly positionals: readonly string[];
  /** 空の値が書かれたオプションの宣言名(最初の 1 つ)。 */
  readonly blankValueOf: string | null;
}

/** 値を取るオプションの値と、それが次のトークンを食べたかを返す。 */
function valueAt(
  head: readonly string[],
  index: number,
  token: string,
): { readonly value: string | undefined; readonly consumed: boolean } {
  if (token.includes("=")) {
    return { value: token.split("=").slice(1).join("="), consumed: false };
  }
  const next = head[index + 1];
  return next === undefined || next.startsWith("-")
    ? { value: undefined, consumed: false }
    : { value: next, consumed: true };
}

/** 1 トークンの分類(位置引数 / 宣言済みオプション / それ以外)。 */
type ScannedToken =
  | { readonly kind: "positional"; readonly value: string }
  | {
      readonly kind: "flag";
      readonly declared: string;
      readonly value: string | undefined;
      readonly consumed: boolean;
    }
  | { readonly kind: "ignored" };

function classifyToken(
  head: readonly string[],
  index: number,
  spec: CommandSpec,
  depth: number,
): ScannedToken {
  const token = head[index] ?? "";
  if (!token.startsWith("-") || token === "-") {
    // コマンド名の段(pull / env create)は位置引数として数えない
    return index >= depth ? { kind: "positional", value: token } : { kind: "ignored" };
  }
  // 未宣言オプションはパーサ(UnrecognizedOption)の担当
  const declared = declaredNameOf(token, spec);
  if (declared === null) {
    return { kind: "ignored" };
  }
  if (spec.flags[declared] === "boolean") {
    return { kind: "flag", declared, value: undefined, consumed: false };
  }
  return { kind: "flag", declared, ...valueAt(head, index, token) };
}

/** `--` より前を 1 度だけ走査する(検査ごとに読み直さない)。 */
function scanHead(head: readonly string[], spec: CommandSpec, depth: number): HeadScan {
  const counts = new Map<string, number>();
  const positionals: string[] = [];
  let blankValueOf: string | null = null;

  for (let index = 0; index < head.length; index += 1) {
    const token = classifyToken(head, index, spec, depth);
    if (token.kind === "positional") {
      positionals.push(token.value);
      continue;
    }
    if (token.kind === "ignored") {
      continue;
    }
    counts.set(token.declared, (counts.get(token.declared) ?? 0) + 1);
    if (token.consumed) {
      index += 1;
    }
    if (blankValueOf === null && token.value !== undefined && isBlank(token.value)) {
      blankValueOf = token.declared;
    }
  }

  return { counts, positionals, blankValueOf };
}

function blankValueRejection(scan: HeadScan): string | null {
  return scan.blankValueOf === null
    ? null
    : `オプション --${scan.blankValueOf} の値が空です(空の値は「未指定」と区別できないため受け付けません)`;
}

function duplicateRejection(scan: HeadScan): string | null {
  for (const [declared, count] of scan.counts) {
    if (count > 1) {
      // gunshi(last-wins)と effect/unstable/cli(first-wins)で**勝つ側が
      // 違う**。どちらを意図したかは読み取れないので、勝者を語らずに落とす
      return `オプション --${declared} を複数回指定しています。どちらの指定を意図したか読み取れないため受け付けません — 1 回だけ書いてください`;
    }
  }
  return null;
}

function blankPositionalRejection(scan: HeadScan, spec: CommandSpec): string | null {
  for (const [index, value] of scan.positionals.entries()) {
    if (isBlank(value)) {
      const name = spec.positionals[index] ?? spec.positionals[0] ?? "";
      return `位置引数 ${name} が空です(空白だけの値も受け付けません)`;
    }
  }
  return null;
}

/** `maruhi run npm test`(`--` 忘れ)。実行対象は `--` の後ろからしか取らない。 */
function restOnlyRejection(scan: HeadScan, spec: CommandSpec): string | null {
  return spec.acceptsRest && scan.positionals.length > 0
    ? `余分な引数です(${scan.positionals.length} 個。中身は表示しません — 平文の値が混ざりうるため)。maruhi run は位置引数を取りません${spec.strayHint ?? ""}`
    : null;
}

function missingRestRejection(rest: readonly string[] | null, spec: CommandSpec): string | null {
  if (spec.restRequired === undefined) {
    return null;
  }
  const command = rest ?? [];
  return command.length === 0 || isBlank(command[0]) ? spec.restRequired : null;
}

/**
 * パーサが黙って通してしまう「maruhi の規律違反」を、コマンド本体より前に
 * 落とす。effect/unstable/cli が構造的に塞ぐ形(未宣言オプション・boolean
 * への値・`--` 跨ぎ・位置引数の過不足)はここに書かない — 二重管理になる。
 *
 * ここに残るのは**パーサの正しさではなく maruhi の方針**である 3 つだけ:
 * 重複指定・空の値・空の位置引数(+ `maruhi run` の「実行対象は `--` の
 * 後ろから」)。
 */
function preflight(argv: readonly string[], commandKey: string): string | null {
  const spec = SPECS[commandKey];
  if (spec === undefined) {
    return null;
  }
  const { head, rest } = splitAtTerminator(argv);
  const scan = scanHead(head, spec, commandKey.split(" ").length);
  // 並び順 = 「実行の形そのもの → 値の書き方」(args.ts と同じ規律)
  const checks: readonly (() => string | null)[] = [
    () => blankValueRejection(scan),
    () => duplicateRejection(scan),
    () => blankPositionalRejection(scan, spec),
    () => restOnlyRejection(scan, spec),
    () => missingRestRejection(rest, spec),
  ];
  for (const check of checks) {
    const rejection = check();
    if (rejection !== null) {
      return rejection;
    }
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/* 診断(構造化フィールドから組み直す — パーサの英文をそのまま出さない)      */
/* -------------------------------------------------------------------------- */

/**
 * `ShowHelp.errors` を maruhi の文面へ写す。
 *
 * **重要**: effect/unstable/cli の既定の文面は打たれた語をそのまま含む
 * (`Unexpected positional argument: "..."`)。位置引数には平文の値が
 * 書かれうる(`maruhi push API_KEY "$SECRET"` の形)ので、既定の描画は
 * 使わず(`renderErrors: false`)、**構造化フィールドのうち安全なものだけ**
 * から組み直す。安全なのは宣言名・候補・個数で、危険なのは
 * `UnexpectedArgument.arguments` と `InvalidValue.value`。
 */
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
  const declared = Object.keys(spec?.flags ?? {}).map((name) => `--${name}`);
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

function unknownSubcommandMessage(error: CliError.UnknownSubcommand): string {
  const guess = error.suggestions[0];
  return `不明なコマンドです${guess === undefined ? "" : `(${guess} のことですか?)`}`;
}

// 判定は instanceof で行う(`_tag` への直接アクセスは oxlint が禁止する —
// src/failure.ts と同じ規律)。
export function describeError(error: CliError.NonShowHelpErrors, commandKey: string): string {
  const spec = SPECS[commandKey];
  if (error instanceof CliError.UnrecognizedOption) {
    return unrecognizedOptionMessage(error, spec);
  }
  if (error instanceof CliError.UnexpectedArgument) {
    return unexpectedArgumentMessage(error, spec, commandKey);
  }
  if (error instanceof CliError.MissingArgument) {
    return `位置引数 ${bareName(error.argument)} を指定してください`;
  }
  if (error instanceof CliError.MissingOption) {
    return `オプション --${bareName(error.option)} を指定してください`;
  }
  if (error instanceof CliError.InvalidValue) {
    // error.value は出さない(平文でありうる)
    return `オプション --${bareName(error.option)} の値が ${error.expected} として読めません`;
  }
  if (error instanceof CliError.UnknownSubcommand) {
    return unknownSubcommandMessage(error);
  }
  return "引数の書き方が正しくありません";
}

/* -------------------------------------------------------------------------- */
/* ランナー                                                                    */
/* -------------------------------------------------------------------------- */

/** 打たれた argv からコマンドの段を組む(検査・診断の宛先を決めるだけ)。 */
function commandKeyOf(argv: readonly string[]): string {
  const head = argv.filter((token) => !token.startsWith("-"));
  const first = head[0] ?? "";
  if (first === "env") {
    return head[1] === undefined ? "env" : `env ${head[1]}`;
  }
  return first;
}

const NON_AGENT: AgentProfile = { isAgent: false };

/**
 * Runs the spike CLI and returns the exit code with captured streams.
 *
 * stdout はコマンドの出力だけ、診断とヘルプは stderr、書き方の誤りは exit 2。
 */
export async function runSpikeCli(
  argv: readonly string[],
  options?: SpikeOptions,
): Promise<SpikeOutcome> {
  const stdout: string[] = [];
  const stderr: string[] = [];
  let invoked: SpikeInvocation | null = null;

  const commandKey = commandKeyOf(argv);
  const rejection = preflight(argv, commandKey);
  if (rejection !== null) {
    stderr.push(`maruhi: ${rejection}`);
    return { exitCode: 2, stdout, stderr, invoked };
  }

  const root = makeCommands((invocation) => {
    invoked = invocation;
  }, options?.agent ?? NON_AGENT);

  // ヘルプ描画(Console.log)を stderr へ寄せる。これをしないと
  // `V=$(maruhi config get server)` がヘルプ本文を捕まえる(gunshi の
  // renderHeader と同じ事故 — 出所が違うだけで形は同じ)
  const capturingConsole: Console.Console = Object.assign(Object.create(console), {
    log: (...args: ReadonlyArray<unknown>) => stderr.push(args.join(" ")),
    error: (...args: ReadonlyArray<unknown>) => stderr.push(args.join(" ")),
  });

  const services = Layer.mergeAll(
    FileSystem.layerNoop({}),
    Path.layer,
    Stdio.layerTest({}),
    Layer.succeed(
      Terminal.Terminal,
      Terminal.make({
        columns: Effect.succeed(80),
        rows: Effect.succeed(24),
        readInput: Effect.die("スパイクでは対話入力を使わない"),
        readLine: Effect.die("スパイクでは対話入力を使わない"),
        display: () => Effect.void,
      }),
    ),
    Layer.succeed(
      ChildProcessSpawner.ChildProcessSpawner,
      ChildProcessSpawner.make(() => Effect.die("スパイクでは子プロセスを起動しない")),
    ),
    Layer.succeed(Console.Console, capturingConsole),
  );

  const exit = await Effect.runPromise(
    Command.runWith(root, { version: "0.0.0-spike", renderErrors: false })([...argv]).pipe(
      Effect.provide(services),
      Effect.exit,
    ),
  );

  if (Exit.isSuccess(exit)) {
    return { exitCode: 0, stdout, stderr, invoked };
  }

  const failure: unknown = Exit.isFailure(exit) ? extractFailure(exit) : null;
  if (failure instanceof CliError.ShowHelp) {
    if (failure.errors.length === 0) {
      // `--help` / `--version` は誤りではない(exit 0)。本文は stderr 側
      return { exitCode: 0, stdout, stderr, invoked };
    }
    for (const error of failure.errors) {
      stderr.push(`maruhi: ${describeError(error, commandKey)}`);
    }
    return { exitCode: 2, stdout, stderr, invoked };
  }

  const maruhiError = failure as MaruhiCliError | null;
  const message =
    maruhiError !== null && typeof maruhiError.message === "string"
      ? maruhiError.message
      : "内部エラー";
  stderr.push(`maruhi: ${message}`);
  return {
    exitCode: maruhiError?.usage === true ? 2 : 1,
    stdout,
    stderr,
    invoked,
  };
}

/** Exit の失敗値を 1 つ取り出す。 */
function extractFailure(exit: Exit.Exit<unknown, unknown>): unknown {
  return Exit.isFailure(exit) ? Cause.squash(exit.cause) : null;
}
