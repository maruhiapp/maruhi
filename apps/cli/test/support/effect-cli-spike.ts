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
// **自前実装は置かない**方針で組んである。引数の検査はすべて Effect の宣言:
// - 重複指定  → `Flag.atMost(1)`
// - 空 / 空白だけの値 → `Flag.withSchema(NonBlank)`(Schema)
// - 実行対象の必須   → `Argument.atLeast(1)`
// - 終了コード       → `Runtime.errorExitCode`(エラー型が自分で持つ)
// - 対話端末の判定   → `Stdio.stdinIsTerminal` / `stdoutIsTerminal`
//
// 本番の src/cli.ts は触っていない(gunshi のまま)。ここは測定用の実装で、
// 採用が決まったら src へ昇格させる。オペレーション本体(pullVariables /
// runOp / envCreateOp)は引数層の測定に関係しないため、呼び出しの記録に
// 置き換えてある — 検査対象は**引数層と診断**であって通信・復号ではない。
//
// 実測の結論は docs/notes/cli-parser-alternatives.md §6-§8 に書いた。

import {
  Cause,
  Console,
  Effect,
  Exit,
  FileSystem,
  Layer,
  Path,
  Runtime,
  Schema,
  Stdio,
  Terminal,
} from "effect";
import { Argument, CliError, Command, Flag } from "effect/unstable/cli";
import { ChildProcessSpawner } from "effect/unstable/process";

import { type AgentProfile, AgentProfileRef, valueDisplayRejection } from "./agent-gate.ts";

/** コマンドごとの宣言(診断の文面を組むためだけに持つ — 検査は Flag 側)。 */
interface CommandSpec {
  readonly flags: readonly string[];
  readonly positionals: readonly string[];
  /** 余分な引数を拒否するときに添えるコマンド固有の助言。 */
  readonly strayHint?: string | undefined;
}

/** `maruhi run` の実行対象が無い / 空のときの案内(src/run.ts と同じ文面)。 */
const RUN_COMMAND_REQUIRED =
  "実行するコマンドを `--` の後に指定してください(例: maruhi run -- printenv MY_VAR)";

const RUN_STRAY_HINT =
  "。実行するコマンドは `--` の後に並べてください(例: maruhi run -- printenv MY_VAR)";

const SPECS: Readonly<Record<string, CommandSpec>> = {
  pull: { flags: ["server", "project", "env", "show"], positionals: [] },
  run: { flags: ["server", "project", "env"], positionals: [], strayHint: RUN_STRAY_HINT },
  "env create": { flags: ["server", "project", "name"], positionals: ["environment-id"] },
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

/** 実行時に差し替える環境(既定は「非エージェントの対話端末」)。 */
export interface SpikeOptions {
  readonly agent?: AgentProfile | undefined;
  readonly stdinIsTerminal?: boolean | undefined;
  readonly stdoutIsTerminal?: boolean | undefined;
}

/* -------------------------------------------------------------------------- */
/* 宣言(検査は Effect の機構に載せる — 自前の走査を書かない)                 */
/* -------------------------------------------------------------------------- */

/**
 * 空・空白だけの値を受け付けない文字列。
 *
 * gunshi では自前の走査(args.ts の emptyOptionValueRejection)だったものが、
 * Schema の宣言 1 つになる。`maruhi push API_KEY --env "$ENV"` で ENV が
 * 未設定のとき、既定環境へ黙って書き込む事故を塞ぐ。
 */
const NonBlank = Schema.String.check(
  Schema.isPattern(/\S/, { message: "空でない値(空白だけの値も受け付けません)" }),
);

/**
 * 値を取るオプション 1 つ。
 *
 * `atMost(1)` が**重複指定の拒否**(gunshi: last-wins で沈黙 /
 * effect: first-wins で沈黙)を宣言で表す。`maruhi pull --no-show $FLAGS` が
 * 全シークレットを表示していた事故(ef7cba1)と同じ形をここで塞ぐ。
 */
function singleValued(name: string) {
  return Flag.string(name).pipe(
    Flag.withSchema(NonBlank),
    Flag.atMost(1),
    Flag.map((values) => values[0]),
  );
}

/* -------------------------------------------------------------------------- */
/* コマンド定義                                                                */
/* -------------------------------------------------------------------------- */

function makeCommands(record: (invocation: SpikeInvocation) => void) {
  const pull = Command.make(
    "pull",
    {
      server: singleValued("server"),
      project: singleValued("project"),
      env: singleValued("env"),
      show: Flag.boolean("show"),
    },
    (values) =>
      Effect.gen(function* () {
        // 値の表示可否はコマンド入口 = 復号前に見る(復号された平文を作らない)
        if (values.show) {
          yield* valueDisplayRejection;
        }
        record({ command: "pull", values });
      }),
  );

  const run = Command.make(
    "run",
    {
      server: singleValued("server"),
      project: singleValued("project"),
      env: singleValued("env"),
      // `--` の後ろはここに入る(空文字列も保持される)。`atLeast(1)` が
      // 「実行対象のない実行」を、`filter` が「実行対象が空文字列」
      // (`maruhi run -- "$CMD"` の未設定形)を落とす。どちらも宣言で、
      // 2 つ目以降の空文字列は**子プロセスの引数として保つ**
      rest: Argument.string("command").pipe(
        Argument.atLeast(1),
        Argument.filter(
          (command) => (command[0] ?? "").trim() !== "",
          () => RUN_COMMAND_REQUIRED,
        ),
      ),
    },
    (values) =>
      Effect.sync(() => {
        const { rest, ...flags } = values;
        record({ command: "run", values: flags, rest: [...rest] });
      }),
  );

  const envCreate = Command.make(
    "create",
    {
      server: singleValued("server"),
      project: singleValued("project"),
      name: singleValued("name"),
      environmentId: Argument.string("environment-id").pipe(Argument.withSchema(NonBlank)),
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
/* 診断(構造化フィールドから組み直す — パーサの英文をそのまま出さない)      */
/* -------------------------------------------------------------------------- */

/**
 * `ShowHelp.errors` を maruhi の文面へ写す。
 *
 * **ここだけは自前**である必要がある: effect/unstable/cli の既定の文面は
 * 打たれた値をそのまま含む(`Invalid value for flag --env: "  "` /
 * `Unexpected positional argument: "..."`)。位置引数・オプション値には
 * 平文が書かれうる(`maruhi push API_KEY "$SECRET"` の形)ので、既定の描画は
 * 使わず(`renderErrors: false`)、**構造化フィールドのうち安全なものだけ**
 * から組み直す。安全なのは宣言名・候補・個数。
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
 * `expected` は宣言側の語彙(`at most 1 value` / `at least 1 value` /
 * Schema のメッセージ)なので出してよい。`value` は打たれた値なので出さない。
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
  return error.kind === "argument"
    ? `位置引数 ${name} の値が受け付けられません(${expectation})`
    : `オプション --${name} の値が受け付けられません(${expectation})`;
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
  return "引数の書き方が正しくありません";
}

/* -------------------------------------------------------------------------- */
/* ランナー                                                                    */
/* -------------------------------------------------------------------------- */

/** 打たれた argv からコマンドの段を組む(診断の宛先を決めるだけ)。 */
function commandKeyOf(argv: readonly string[]): string {
  const head = argv.filter((token) => !token.startsWith("-"));
  const first = head[0] ?? "";
  if (first === "env") {
    return head[1] === undefined ? "env" : `env ${head[1]}`;
  }
  return first;
}

/**
 * `maruhi run` は `--` の後ろからしか実行対象を取らない。
 *
 * これはパーサの正しさではなく **maruhi の方針**(`maruhi run npm test --env x`
 * の `--env` が maruhi のものか子プロセスのものか読めなくなる)。Effect の
 * 宣言では表せないので、ここだけ argv を見る。方針を緩めるなら丸ごと消える。
 */
function terminatorRequired(argv: readonly string[], commandKey: string): string | null {
  if (commandKey !== "run" || argv.includes("--")) {
    return null;
  }
  const strayCount = argv.slice(1).filter((token) => !token.startsWith("-")).length;
  return strayCount === 0
    ? null
    : `余分な引数です(${strayCount} 個。中身は表示しません — 平文の値が混ざりうるため)。maruhi run は位置引数を取りません${RUN_STRAY_HINT}`;
}

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
  const rejection = terminatorRequired(argv, commandKey);
  if (rejection !== null) {
    stderr.push(`maruhi: ${rejection}`);
    return { exitCode: 2, stdout, stderr, invoked };
  }

  const root = makeCommands((invocation) => {
    invoked = invocation;
  });

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
    // TTY の有無は Effect のサービス経由で差し替える(process.stdout.isTTY を
    // 直に読まない)。エージェント検出の一次境界がこれ(agent-gate.ts)
    Stdio.layerTest({
      stdinIsTerminal: Effect.succeed(options?.stdinIsTerminal ?? true),
      stdoutIsTerminal: Effect.succeed(options?.stdoutIsTerminal ?? true),
    }),
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
      Effect.provideService(AgentProfileRef, options?.agent ?? { isAgent: false }),
      Effect.provide(services),
      Effect.exit,
    ),
  );

  if (Exit.isSuccess(exit)) {
    return { exitCode: 0, stdout, stderr, invoked };
  }

  const failure: unknown = Cause.squash(exit.cause);
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

  // 終了コードはエラー型が自分で持つ(Runtime.errorExitCode)。写像表を
  // ランナー側に書かない — runMain の既定 teardown が同じ値を読む
  const message = failure instanceof Error ? failure.message : "内部エラー";
  return {
    exitCode: exitCodeOf(failure),
    stdout: stdout,
    stderr: [...stderr, `maruhi: ${message}`],
    invoked,
  };
}

/** `Runtime.errorExitCode` を持つエラーはその値、無ければ実行の失敗(1)。 */
function exitCodeOf(failure: unknown): number {
  const marked = failure as { readonly [Runtime.errorExitCode]?: number } | null;
  return marked?.[Runtime.errorExitCode] ?? 1;
}
