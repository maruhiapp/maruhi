// `effect/unstable/cli` へ移した引数層(ADR-0016 の第 1 段階: pull / run /
// env create の 3 コマンド)。残る 11 コマンドと `env rotate` / `env diff` は
// gunshi のまま(cli.ts)で、この分割状態は移行が進むまで続く。
//
// 規律(ADR-0016 の決定):
//
// 1. **引数の検査に自前の走査を書かない**。すべて宣言で表す —
//    重複指定 = `Flag.atMost(1)`(**boolean にも付ける**)、空 / 空白だけの値 =
//    `Flag.withSchema`、実行対象の必須 = `Argument.atLeast(1)` / `Argument.filter`
// 2. **打たれた値を診断に出さない**。文面は `CliOutput.Formatter`
//    (cli-formatter.ts)で組み直す
// 3. **終了コードはエラー型が持つ**(`Runtime.errorExitCode` — errors.ts)。
//    唯一の例外 `ShowHelp` は teardown で 2 へ読み替える(cli-teardown.ts)
// 4. **組み込みグローバルフラグは `--help` / `--version` だけ**に絞る。既定では
//    `--wizard` / `--completions` / `--log-level` が全コマンドへ生え、
//    `maruhi pull --wizard` は**対話ウィザードが実際に起動する**(実測)
// 5. **`process.*` を直に読まない**。argv も端末の有無も `Stdio` サービス経由
// 6. **stdout はコマンドの出力だけ**。コマンド本体の出力は `CliIo.log`、
//    ヘルプ・診断は `Console`(= `CliIo.logError` = stderr)へ分ける

import { isEnvironmentId } from "@maruhi/core";
import {
  Cause,
  Console,
  Effect,
  Exit,
  FileSystem,
  Layer,
  Path,
  Schema,
  Stdio,
  Terminal,
} from "effect";
import {
  Argument,
  CliConfig,
  CliError as EffectCliError,
  Command,
  Flag,
  GlobalFlag,
  type Param,
} from "effect/unstable/cli";
import { ChildProcessSpawner } from "effect/unstable/process";

import { ensureValueDisplayAllowed } from "./agent-gate.ts";
import { type CommandSpec, formatterLayer, NON_BLANK_MESSAGE } from "./cli-formatter.ts";
import { maruhiTeardown } from "./cli-teardown.ts";
import type { CliServices, CommonFlags } from "./context.ts";
import { openEnvironment, openProject } from "./context.ts";
import { formatPulledLine, logWarnings, showValues } from "./display.ts";
import { envCreateOp } from "./env-create.ts";
import { CliError, usageError } from "./errors.ts";
import { internalErrorKind } from "./failure.ts";
import { CliIo, type CliIoShape } from "./io.ts";
import { type PulledVariables, pullVariables } from "./pull.ts";
import { RUN_COMMAND_REQUIRED, runOp } from "./run.ts";
import { CLI_VERSION } from "./version.ts";

/** `--` を書き忘れた実行に添える案内(実行対象の渡し方は 1 つだけ)。 */
const RUN_TERMINATOR_HINT =
  "。実行するコマンドは `--` の後に並べてください(例: maruhi run -- printenv MY_VAR)";

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
 *
 * `noUncheckedIndexedAccess: true` なので結果は `string | undefined` =
 * context.ts の {@link CommonFlags} とそのまま噛み合う(Option へ変換しない)。
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
 * **boolean にも `atMost(1)` が要る**: 素の `Flag.boolean` は重複を沈黙で解決し、
 * **打った順で結果が変わる**(実測: `--show --no-show` は first-wins で `true`、
 * `--no-show --show` は `false`)。`maruhi pull --no-show $FLAGS` の `$FLAGS` に
 * `--show` が混ざる形(ef7cba1)は順序に依存させてはいけない。
 */
function singleFlag(name: string) {
  return Flag.boolean(name).pipe(
    Flag.atMost(1),
    Flag.map((values) => values[0] ?? false),
  );
}

/**
 * 診断用のコマンド宣言を、**コマンド定義そのもの**から導く。
 *
 * 手書きの写しを持つと、フラグを足したときに診断だけ古いまま残る。`Param` は
 * 公開型として `kind`(`"flag"` / `"argument"`)を持つので、宣言の並びから
 * そのまま仕分けできる。名前はオブジェクトのキー(= 打つときの綴り)を使う。
 */
function specOf(config: Readonly<Record<string, Param.Any>>): CommandSpec {
  const flags: string[] = [];
  const positionals: string[] = [];
  for (const [name, param] of Object.entries(config)) {
    (param.kind === "flag" ? flags : positionals).push(name);
  }
  return { flags, positionals };
}

/* -------------------------------------------------------------------------- */
/* コマンド定義                                                                */
/* -------------------------------------------------------------------------- */

/** 全 3 コマンドが取る共通フラグ(context.ts の CommonFlags と同じ名前)。 */
const commonFlags = () => ({
  server: singleValued("server"),
  project: singleValued("project"),
  env: singleValued("env"),
});

const pullConfig = { ...commonFlags(), show: singleFlag("show") };

const runConfig = {
  ...commonFlags(),
  // `--` の後ろはここに入る(空文字列も保持される)。`atLeast(1)` が
  // 「実行対象のない実行」を、`filter` が「実行対象が空文字列」
  // (`maruhi run -- "$CMD"` の未設定形)を落とす。どちらも宣言で、
  // 2 つ目以降の空文字列は**子プロセスの引数として保つ**
  command: Argument.string("command").pipe(
    Argument.atLeast(1),
    Argument.filter(
      (command) => (command[0] ?? "").trim() !== "",
      () => RUN_COMMAND_REQUIRED,
    ),
  ),
};

const envCreateConfig = {
  server: singleValued("server"),
  project: singleValued("project"),
  name: singleValued("name"),
  // キーは**打つときの綴り**にする(specOf が診断名としてそのまま使う)
  "environment-id": Argument.string("environment-id").pipe(Argument.withSchema(NonBlank)),
};

/** commandKey → 診断用の宣言。キーは runCli の振り分けが返すものと同じ。 */
export const COMMAND_SPECS: Readonly<Record<string, CommandSpec>> = {
  pull: specOf(pullConfig),
  run: specOf(runConfig),
  "env create": specOf(envCreateConfig),
};

/**
 * `maruhi run` が実行するコマンド列を確定する(**`--` の後ろだけ**)。
 *
 * パーサは `--` の前後の位置引数を 1 つの配列にまとめる(実測: 上流の
 * `parseArgs` が `[...result.arguments, ...afterEndOfOptions]`)。したがって
 * 宣言だけでは `maruhi run stray -- printenv` が `stray` の実行に化ける。
 * ADR-0016 決定 8(`--` を必須とし、判定は `Stdio.args` を読む)の実装として、
 * **`--` の後ろの個数と一致すること**まで見る。
 *
 * 個数は**パーサが解決した配列と argv の位置**から出す(宣言の写しを持たない
 * — 値を取るフラグを足したときに黙ってずれる)。中身は診断に出さない。
 */
function commandAfterTerminator(
  parsed: readonly string[],
): Effect.Effect<readonly string[], CliError, Stdio.Stdio> {
  return Effect.gen(function* () {
    const stdio = yield* Stdio.Stdio;
    const argv = yield* stdio.args;
    const terminator = argv.indexOf("--");
    // `--` が無い分岐では、可変長引数がそのまま余分な位置引数になる
    // (`--env prod` の `prod` はフラグの値として食べられている)
    const stray = terminator < 0 ? parsed.length : parsed.length - (argv.length - terminator - 1);
    if (stray > 0) {
      return yield* Effect.fail(
        usageError(
          `余分な引数です(${stray} 個。中身は表示しません — 平文の値が混ざりうるため)。maruhi run は \`--\` より前に位置引数を取りません${RUN_TERMINATOR_HINT}`,
        ),
      );
    }
    return parsed;
  });
}

/**
 * `maruhi env create <id>` の本体(複合リクエスト — §12-4)。
 *
 * **移行中は gunshi 側の env コマンド(cli.ts)も同じ本体を呼ぶ**: 引数層が
 * 2 つある間に実装まで 2 つ持つと、片方だけ直す事故が起きる。次段で env を
 * まるごと移したときにこの共有は消える。
 */
export function envCreateCommand(
  flags: CommonFlags & { readonly name?: string | undefined },
  environmentId: string,
): Effect.Effect<void, CliError, CliServices> {
  return Effect.gen(function* () {
    const io = yield* CliIo;
    const context = yield* openProject(flags);
    const created = yield* envCreateOp({
      client: context.client,
      verified: context.verified,
      environmentId,
      name: flags.name ?? environmentId,
      signerUserId: context.session.userId,
      signingKeyPair: context.masterKeys.sigKeyPair,
      resync: context.resync,
    });
    yield* io.log(
      // メンバー数は**実際に登録したラップ集合**の大きさ(CAS リトライで作り
      // 直した場合、コマンド開始時のビューのメンバー数とは食い違いうる)
      `環境を作成しました: ${environmentId}(epoch=${created.currentEpoch}、DEK を現メンバー ${created.memberCount} 名へラップ済み)`,
    );
  });
}

/** 位置引数で受けた環境 ID の形式検証(**指定値そのものはエラーに出さない**)。 */
function requireEnvironmentId(value: string): Effect.Effect<string, CliError> {
  return isEnvironmentId(value)
    ? Effect.succeed(value)
    : Effect.fail(
        usageError(
          "環境 ID の形式が正しくありません(英数字で始まり、英数字と _ - が続く 64 字まで。例: maruhi env create dev)",
        ),
      );
}

/**
 * コマンド本体。ハンドラは `Effect<void>` しか返せない(`Command.runWith` が
 * 値を捨てる)ので、子プロセスの終了コードは `onExitCode` で持ち出す。
 */
function makeRootCommand(onExitCode: (code: number) => void) {
  const pull = Command.make("pull", pullConfig, (values) =>
    Effect.gen(function* () {
      const io = yield* CliIo;
      // 値の表示拒否はコマンド入口 = **復号前**に検査する(環境全体を復号して
      // から拒否しない = 復号された平文をそもそも作らない)。復号後の
      // showValues にも同じ検査があり、そちらは防衛線(display.ts)
      if (values.show) {
        yield* ensureValueDisplayAllowed;
      }
      const context = yield* openEnvironment(values);
      const pulled: PulledVariables = yield* pullVariables({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        recipient: context.recipient,
        resync: context.resync,
        floor: context.floorHandle,
      });
      yield* logWarnings(pulled.warnings);
      yield* io.log(
        `同期・検証 OK: ${pulled.variables.length} 変数(環境 ${context.environmentId})`,
      );
      for (const variable of pulled.variables) {
        yield* io.log(formatPulledLine(variable));
      }
      if (values.show) {
        yield* showValues(pulled.variables);
      }
    }),
  ).pipe(Command.withDescription("同期検査(§6.3)+ 配布時検証(§5.1)+ 復号し、メタデータを表示する"));

  const run = Command.make("run", runConfig, (values) =>
    Effect.gen(function* () {
      const { command: parsed, ...flags } = values;
      // 通信・復号より前(コマンド本体の先頭)で落とす
      const command = yield* commandAfterTerminator(parsed);
      const context = yield* openEnvironment(flags);
      const pulled = yield* pullVariables({
        client: context.client,
        verified: context.verified,
        environmentId: context.environmentId,
        recipient: context.recipient,
        resync: context.resync,
        floor: context.floorHandle,
      });
      yield* logWarnings(pulled.warnings);
      // 環境変数名は検証済みステートメント経由(§4.2 / §12-7)。実行制御系
      // 変数名 denylist(run.ts)は検証済み name に適用される防衛層
      onExitCode(yield* runOp({ command, variables: pulled.variables }));
    }),
  ).pipe(
    Command.withDescription(
      "pull + 復号した値を子プロセスの環境変数へメモリ注入してコマンドを実行する",
    ),
  );

  const envCreate = Command.make("create", envCreateConfig, (values) =>
    Effect.gen(function* () {
      // 形式は宣言(NonBlank)を通った後の追加検査。ネットワークより前に見る
      const environmentId = yield* requireEnvironmentId(values["environment-id"]);
      yield* envCreateCommand(values, environmentId);
    }),
  ).pipe(Command.withDescription("環境を作成する(複合リクエスト — §12-4)"));

  // gunshi は 1 段(サブコマンド + positional の action)しか組めないため、
  // maruhi は create / rotate / diff を**位置引数**にしていた。その結果
  // 1 つの引数表に全操作のフラグが同居し、「その操作に適用されない
  // オプション」の拒否(cli.ts の ENV_ACTION_FLAGS / optionRestrictedTo)を
  // 自前で書く必要があった。入れ子のサブコマンドはその機構ごと不要にする
  const env = Command.make("env").pipe(Command.withSubcommands([envCreate]));

  return Command.make("maruhi").pipe(Command.withSubcommands([pull, run, env]));
}

/* -------------------------------------------------------------------------- */
/* ランナー                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * 引数層が使う Effect の環境のうち、**maruhi が使わない**もの。
 *
 * ファイル・端末・子プロセスは maruhi 自身のサービス(ConfigStore /
 * CliIo.promptLine / ProcessRunner)が受け持つ。引数層へ実装を渡すと、
 * 宣言していない対話経路・出力経路(Prompt / wizard)が動く余地を残すので、
 * ここでは**死ぬ実装**を置く(決定 5 と同じ理由)。
 */
const unusedEnvironment = Layer.mergeAll(
  FileSystem.layerNoop({}),
  Path.layer,
  Layer.succeed(
    Terminal.Terminal,
    Terminal.make({
      columns: Effect.succeed(80),
      rows: Effect.succeed(24),
      readInput: Effect.die("引数層は対話入力を使わない(対話は CliIo.promptLine)"),
      readLine: Effect.die("引数層は対話入力を使わない(対話は CliIo.promptLine)"),
      display: () => Effect.void,
    }),
  ),
  Layer.succeed(
    ChildProcessSpawner.ChildProcessSpawner,
    ChildProcessSpawner.make(() => Effect.die("子プロセスの起動は ProcessRunner(run.ts)")),
  ),
);

/**
 * ヘルプ・診断の宛先。**全メソッド**を `CliIo.logError`(= stderr)へ寄せる
 * (決定 9)。log / error だけの部分上書きだと、上流が描画メソッドを増やした
 * ときに実 stdout へ素通りする穴ができる。
 *
 * `Console` のメソッドは同期(`void`)なので、ここでは行を溜めて実行後に
 * `CliIo` へ流す(Effect を `runSync` で割り込ませない)。
 */
function collectingConsole(lines: string[]): Console.Console {
  const collect = (...args: ReadonlyArray<unknown>) => {
    lines.push(args.join(" "));
  };
  return {
    assert: collect,
    clear: collect,
    count: collect,
    countReset: collect,
    debug: collect,
    dir: collect,
    dirxml: collect,
    error: collect,
    group: collect,
    groupCollapsed: collect,
    groupEnd: collect,
    info: collect,
    log: collect,
    table: collect,
    time: collect,
    timeEnd: collect,
    timeLog: collect,
    trace: collect,
    warn: collect,
  };
}

/**
 * argv を `Stdio` へ載せ替える。
 *
 * runCli は argv を引数で受け取る(テストが実行ごとに argv を差し替えるため)
 * ので、`--` の判定(`commandAfterTerminator`)が見る `Stdio.args` も**同じ
 * 配列**にする。本番の `Stdio.args` は `process.argv.slice(2)` = bin.ts が
 * runCli へ渡すものと同一なので、値は変わらず出所だけが 1 つになる。
 */
function withArgs(stdio: Stdio.Stdio, argv: readonly string[]): Stdio.Stdio {
  return Stdio.make({ ...stdio, args: Effect.succeed([...argv]) });
}

/** 実行の失敗を maruhi の語彙で 1 行にする(上流の英文を素通しにしない)。 */
function reportFailure(io: CliIoShape, cause: Cause.Cause<unknown>): Effect.Effect<void> {
  const failure: unknown = Cause.squash(cause);
  // ShowHelp は effect 側が Formatter 経由で描画済み(Console → stderr)
  if (failure instanceof EffectCliError.ShowHelp) {
    return Effect.void;
  }
  if (failure instanceof CliError) {
    return io.logError(`maruhi: ${failure.message}`);
  }
  // defect(バグ)や上流の未知エラー。**message は出さない**: 打たれた値を
  // 埋め込んだ文面(`Invalid value: <平文>`)でも到達しうるので、制御文字の
  // 中和だけでは規律(打たれた値を診断に出さない)を守れない。無言では飲まず
  // (CLAUDE.md)、型の名前だけを添える(failure.ts の internalErrorKind —
  // gunshi 側の defect 経路と同じ形)
  return io.logError(`maruhi: 内部エラー(${internalErrorKind(failure)})`);
}

/**
 * Runs one of the migrated commands (`pull` / `run` / `env create`) through
 * `effect/unstable/cli` and returns the process exit code.
 *
 * `commandKey` は runCli の振り分けが決めた**解決済みのコマンド段**で、診断の
 * 宛先(どの宣言を名指しするか)に使う。
 */
export async function runEffectCli(
  commandKey: string,
  argv: readonly string[],
  layer: Layer.Layer<CliServices>,
): Promise<number> {
  const diagnostics: string[] = [];
  let commandExitCode = 0;
  const root = makeRootCommand((code) => {
    commandExitCode = code;
  });
  // ヘルプの分量だけを決める(`--help` を明示した実行は全文、書き方の誤りに
  // 添えるのは使い方 1 行 — 決定 3)。引数の**検査**には一切使わない。
  // `--` の後ろは**子プロセスの引数**なので見ない: `maruhi run stray -- cmd -h`
  // の `-h` は cmd のもので、maruhi へのヘルプ要求ではない
  const terminator = argv.indexOf("--");
  const ownArgs = terminator < 0 ? argv : argv.slice(0, terminator);
  const helpRequested = ownArgs.includes("--help") || ownArgs.includes("-h");

  const program = Effect.gen(function* () {
    const io = yield* CliIo;
    const stdio = yield* Stdio.Stdio;
    const exit = yield* Command.runWith(root, { version: CLI_VERSION })([...argv]).pipe(
      Effect.provideService(Stdio.Stdio, withArgs(stdio, argv)),
      Effect.provideService(Console.Console, collectingConsole(diagnostics)),
      Effect.provide(formatterLayer(commandKey, COMMAND_SPECS, helpRequested)),
      // 組み込みグローバルフラグは --help / --version だけ(決定 5)
      Effect.provide(CliConfig.layer({ builtIns: [GlobalFlag.Help, GlobalFlag.Version] })),
      Effect.provide(unusedEnvironment),
      Effect.exit,
    );
    for (const line of diagnostics) {
      yield* io.logError(line);
    }
    if (Exit.isFailure(exit)) {
      yield* reportFailure(io, exit.cause);
    }
    return exit;
  });

  const exit = await Effect.runPromise(program.pipe(Effect.provide(layer)));

  let exitCode = 0;
  // 本番もテストも同じ teardown を通す(ShowHelp の exit 1 → 2 の読み替えが
  // 片方でしか効かない形を作らない — cli-teardown.ts)
  maruhiTeardown(exit, (code) => {
    exitCode = code;
  });
  // `maruhi run` は子プロセスの終了コードを引き継ぐ。`Command.runWith` は
  // ハンドラの返り値を捨てるため、成功した実行の終了コードだけは持ち出す
  // (エラーではないので Runtime.errorExitCode には載せられない)
  return exitCode === 0 ? commandExitCode : exitCode;
}
