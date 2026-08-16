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
// **自前実装は置かない**方針で組んである。すべて Effect の機構:
// - 重複指定         → `Flag.atMost(1)`
// - 空 / 空白だけの値 → `Flag.withSchema(NonBlank)`(Schema)
// - 実行対象の必須   → `Argument.atLeast(1)` / `Argument.filter`
// - 診断の文面       → `CliOutput.Formatter`(cli-formatter.ts)
// - 終了コード       → `Runtime.errorExitCode`(エラー型が自分で持つ)
// - 対話端末の判定   → `Stdio.stdinIsTerminal` / `stdoutIsTerminal`
// - argv の参照      → `Stdio.args`(process.argv を直に読まない)
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
  Data,
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
import { Argument, CliConfig, CliError, Command, Flag, GlobalFlag } from "effect/unstable/cli";
import { ChildProcessSpawner } from "effect/unstable/process";

import {
  type AgentProfile,
  AgentProfileRef,
  ValueDisplayRefused,
  valueDisplayRejection,
} from "./agent-gate.ts";
import {
  type CommandSpec,
  formatterLayer,
  NON_BLANK_MESSAGE,
  RUN_COMMAND_REQUIRED,
} from "./cli-formatter.ts";
import { maruhiTeardown } from "./cli-teardown.ts";

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

/** スパイク実行の結果。stderr は Console 呼び出し単位、stdout は実ストリームへの書き込み単位で捕捉する。 */
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
const NonBlank = Schema.String.check(Schema.isPattern(/\S/, { message: NON_BLANK_MESSAGE }));

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

/**
 * boolean オプション 1 つ。
 *
 * **boolean にも `atMost(1)` が要る**(レビュー指摘): 素の `Flag.boolean` は
 * 重複を沈黙で解決する(実測: `--show --no-show` は first-wins で `true`)。
 * `maruhi pull --no-show $FLAGS` の `$FLAGS` に `--show` が混ざる形(ef7cba1)
 * は**打った順で結果が変わる**ので、順序に依存させずに落とす。
 */
function singleFlag(name: string) {
  return Flag.boolean(name).pipe(
    Flag.atMost(1),
    Flag.map((values) => values[0] ?? false),
  );
}

/**
 * `maruhi run` に `--` が無い実行の拒否。
 *
 * **パーサの正しさではなく方針**: `--` を挟まないと `maruhi run npm test
 * --env prod` の `--env` が maruhi のものか子プロセスのものか読めない
 * (effect/unstable/cli は maruhi のものとして食べ、子には渡らない)。
 * 「書いたことと逆」を作らないため、`--` を必須にする。
 *
 * 判定材料は `Stdio.args`(process.argv を直に読まない)。終了コードは
 * エラー型が持つ(書き方の誤り = 2)。
 */
export class TerminatorRequired extends Data.TaggedError("TerminatorRequired")<{
  readonly message: string;
}> {
  override readonly [Runtime.errorExitCode] = 2;
}

/** `maruhi run` が取るオプション(いずれも値を取る)。値を余分な引数と数えないため。 */
const RUN_VALUE_FLAGS: ReadonlySet<string> = new Set(["--server", "--project", "--env"]);

/**
 * `--` より前の余分な引数の数。**オプションの値は数えない**(レビュー指摘:
 * `maruhi run --env prod npm test` を 3 個と報告していた)。中身を出さない
 * 方針では個数が唯一の手がかりなので、ずれると診断の価値が落ちる。
 *
 * 先頭は `run`(このコマンドは 1 段)。
 */
function strayCountBeforeTerminator(argv: readonly string[]): number {
  let stray = 0;
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index] ?? "";
    if (token.startsWith("-")) {
      // `--env=prod` は次のトークンを食べない
      if (RUN_VALUE_FLAGS.has(token)) {
        index += 1;
      }
      continue;
    }
    stray += 1;
  }
  return stray;
}

const ensureTerminator = Effect.gen(function* () {
  const stdio = yield* Stdio.Stdio;
  const argv = yield* stdio.args;
  if (argv.includes("--")) {
    return;
  }
  const stray = strayCountBeforeTerminator(argv);
  if (stray > 0) {
    return yield* new TerminatorRequired({
      message: `maruhi: 余分な引数です(${stray} 個。中身は表示しません — 平文の値が混ざりうるため)。maruhi run は位置引数を取りません${RUN_STRAY_HINT}`,
    });
  }
});

/* -------------------------------------------------------------------------- */
/* コマンド定義                                                                */
/* -------------------------------------------------------------------------- */

function makeCommands(record: (invocation: SpikeInvocation) => void, emit: (line: string) => void) {
  const pull = Command.make(
    "pull",
    {
      server: singleValued("server"),
      project: singleValued("project"),
      env: singleValued("env"),
      show: singleFlag("show"),
    },
    (values) =>
      Effect.gen(function* () {
        // 値の表示可否はコマンド入口 = 復号前に見る(復号された平文を作らない)
        if (values.show) {
          yield* valueDisplayRejection;
        }
        record({ command: "pull", values });
        // コマンドの出力は stdout(捕捉して「stdout が汚れていない」検査を
        // 空振りさせない — レビュー指摘)
        emit("同期・検証 OK: 0 変数");
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
      Effect.gen(function* () {
        // 通信・復号より前(コマンド本体の先頭)で落とす
        yield* ensureTerminator;
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
    (values) =>
      Effect.sync(() => {
        record({ command: "env create", values });
        emit("環境を作成しました");
      }),
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

  const root = makeCommands(
    (invocation) => {
      invoked = invocation;
    },
    (line) => {
      process.stdout.write(`${line}\n`);
    },
  );

  // 描画(ヘルプ・診断)は effect/unstable/cli 自身が Console 経由で行う。
  // Console は**全メソッド**を stderr へ寄せる — stdout はコマンドの出力だけ。
  // log / error だけの部分上書き(プロトタイプで素の console に落とす形)だと、
  // 上流が描画メソッドを増やしたときに実ストリームへ素通りする穴ができる
  const toStderr = (...args: ReadonlyArray<unknown>) => {
    stderr.push(args.join(" "));
  };
  const capturingConsole: Console.Console = {
    assert: toStderr,
    clear: toStderr,
    count: toStderr,
    countReset: toStderr,
    debug: toStderr,
    dir: toStderr,
    dirxml: toStderr,
    error: toStderr,
    group: toStderr,
    groupCollapsed: toStderr,
    groupEnd: toStderr,
    info: toStderr,
    log: toStderr,
    table: toStderr,
    time: toStderr,
    timeEnd: toStderr,
    timeLog: toStderr,
    trace: toStderr,
    warn: toStderr,
  };

  const services = Layer.mergeAll(
    FileSystem.layerNoop({}),
    Path.layer,
    // argv も TTY の有無も Effect のサービス経由(process.* を直に読まない)
    Stdio.layerTest({
      args: Effect.succeed([...argv]),
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
    // 診断の文面は Formatter で差し替える(ランナーに描画を書かない)
    formatterLayer(commandKeyOf(argv), SPECS, argv.includes("--help") || argv.includes("-h")),
    // 組み込みグローバルフラグは **--help / --version だけ**に絞る。
    // 既定は wizard / completions / log-level も全コマンドへ生える(実測:
    // `maruhi pull --wizard` は対話ウィザードが起動する)。secrets ツールに
    // 宣言していない対話経路・出力経路を勝手に持たせない
    CliConfig.layer({ builtIns: [GlobalFlag.Help, GlobalFlag.Version] }),
  );

  // **実 fd を捕捉する**(レビュー指摘): 注入した Console 経由の出力だけを
  // 見ていると「stdout が汚れていない」という検査が空振りする。ライブラリが
  // Console を迂回して process.stdout へ書いた場合も捕まえる
  const realWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = ((chunk: string | Uint8Array): boolean => {
    stdout.push(typeof chunk === "string" ? chunk.replace(/\n$/, "") : String(chunk));
    return true;
  }) as typeof process.stdout.write;

  let exit: Exit.Exit<void, unknown>;
  try {
    exit = await Effect.runPromise(
      Command.runWith(root, { version: "0.0.0-spike" })([...argv]).pipe(
        Effect.provideService(AgentProfileRef, options?.agent ?? { isAgent: false }),
        Effect.provide(services),
        Effect.exit,
      ),
    );
  } finally {
    process.stdout.write = realWrite;
  }

  // 終了コードは**本番と同じ teardown**を通して決める(ハーネスで手計算しない
  // — レビュー指摘。ShowHelp は上流が exit 1 を宣言しているため、読み替えが
  // teardown に載っていないと本番だけ 1 になる)
  let exitCode = 0;
  maruhiTeardown(exit, (code) => {
    exitCode = code;
  });

  if (Exit.isSuccess(exit)) {
    return { exitCode, stdout, stderr, invoked };
  }

  // ShowHelp は effect 側が Formatter 経由で描画済み。それ以外は**こちらが
  // 文面を書いた型付きエラーだけ**を出す(上流や未知の Error の message は
  // argv 由来の値を含みうるので素通しにしない — レビュー指摘)
  const failure: unknown = Cause.squash(exit.cause);
  if (failure instanceof ValueDisplayRefused || failure instanceof TerminatorRequired) {
    stderr.push(
      failure.message.startsWith("maruhi:") ? failure.message : `maruhi: ${failure.message}`,
    );
  } else if (!(failure instanceof CliError.ShowHelp)) {
    stderr.push("maruhi: 内部エラー");
  }
  return { exitCode, stdout, stderr, invoked };
}
