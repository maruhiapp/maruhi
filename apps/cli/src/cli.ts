// maruhi CLI のコマンド定義と Effect 実行の結線。
//
// **移行中**(ADR-0016 の第 1〜3 段階): `pull` / `run` / `env` / `server` /
// `invite` / `member` / `push` / `config` / `key` / `project` / `rotation` /
// `audit` は `effect/unstable/cli`(effect-cli.ts)、残り(login / logout)は
// Gunshi のまま。runCli が解決済みのコマンド名で振り分ける(migratedCommandKey)。
//
// Gunshi 側のコマンド階層は 1 段(サブコマンド + positional の action)。
// 値の入力は stdin(argv に平文値を載せない)、値の表示は pull --show のみで、
// 対話端末以外では拒否する(agent-gate.ts)。`maruhi run` は許可される。

import { Effect, Layer } from "effect";
import { cli, define } from "gunshi";

import {
  type ArgCheckContext,
  argsRejection,
  type ArgsCheckOptions,
  commandNameAfterTerminator,
  commandTokens,
  type CommandTable,
  TERMINATOR_BEFORE_COMMAND,
  usageErrorMessages,
} from "./args.ts";
import type { CliServices } from "./context.ts";
import { COMMAND_SPECS, ROOT_SPEC_KEY, runEffectCli } from "./effect-cli.ts";
import type { CliError } from "./errors.ts";
import { internalErrorKind, toCliError } from "./failure.ts";
import { CliIo } from "./io.ts";
import { CLI_VERSION } from "./version.ts";

export type { CliServices } from "./context.ts";

type CliProgram = Effect.Effect<number | void, CliError, CliServices>;

/**
 * 引数の書き方を検査してからコマンド本体(Effect プログラム)を実行し、
 * 終了コードを蓄積する。ctx を必ず渡す形にしてあるので、新しいコマンドが
 * 共通検査(args.ts)を通し忘れることがない。
 */
type Execute = (
  ctx: ArgCheckContext,
  program: CliProgram,
  /** コマンドごとの検査の調整(型と既定は args.ts が持つ)。 */
  options?: ArgsCheckOptions,
) => Promise<void>;

/**
 * Given an action → action-specific-options table, reports whether `action` may
 * use `declared`: null when it may, otherwise the actions the option is
 * restricted to (for naming them in the diagnostic).
 *
 * 判定は「そのオプションを**持つ操作**(自分を含む)」で行う。**「他の操作の分」
 * だけを数えてはならない**: それだと 1 つのオプションを複数の操作が共有する形で、
 * 共有元のどちらでも拒否される(= 宣言したとおりに使えない)。
 *
 * 表を引数に取るのはその形をテストから固定するため。第 3 段階 ③ の audit
 * 移行で CLI 側の利用者は消えた — units.test.ts の単体検査ごと、最終コミット
 * (gunshi 廃止)で削除する(トラップ 11 の申し送り)。
 */
export function optionRestrictedTo<A extends string>(
  actions: readonly A[],
  flags: Readonly<Record<A, ReadonlySet<string>>>,
  action: A,
  declared: string,
): readonly A[] | null {
  const owners = actions.filter((owner) => flags[owner].has(declared));
  // 持ち主が居ない = 全操作で使える共通オプション(--server / --project)。
  // 自分が持ち主なら当然使える(共有していても)
  return owners.length === 0 || owners.includes(action) ? null : owners;
}

function entryCommand(execute: Execute, commands: readonly string[]) {
  return define({
    name: "maruhi",
    description: "maruhi — ディスクレス secrets 管理 CLI",
    run: (ctx) =>
      execute(
        ctx,
        Effect.gen(function* () {
          const io = yield* CliIo;
          yield* io.log("使い方: maruhi <command> [options]");
          // 一覧は登録済みサブコマンドから導く(手書きすると、コマンドを
          // 増やしたときにヘルプだけ古いまま残る)
          yield* io.log(`commands: ${commands.join(" / ")}`);
          yield* io.log("詳細: maruhi <command> --help");
        }),
      ),
  });
}

/**
 * `effect/unstable/cli` へ移したコマンド(ADR-0016 第 1〜2 段階)への振り分け。
 * 戻り値は診断の宛先(解決済みのコマンド段)にそのまま使う。
 *
 * コマンドの解決は **gunshi と同じ規則**(args.ts の commandTokens)で行う。
 * 自前の argv 走査を持たないためと、振り分けから漏れた形が gunshi 側で
 * 「不明なコマンドです」になる — 実在するコマンドについて嘘をつく — のを
 * 避けるため。`--` の後ろはコマンドの段ではないので見ない(先頭のコマンド名を
 * `--` の後ろへ書いた形は commandNameAfterTerminator が手前で落とす)。
 *
 * 入れ子の段(`env`)は先頭のコマンド名で丸ごと移行済みへ振り分ける。2 語目が
 * 既知のサブコマンドなら診断の宛先をその段(`env rotate`)まで確定し、そうで
 * なければ親の段(`env`)のまま渡す — 不明なサブコマンドの診断は effect 側
 * (UnknownSubcommand)が受け持つ。段の一覧は COMMAND_SPECS から引く
 * (手書きの写しを持たない)。
 */
function migratedCommandKey(argv: readonly string[]): string | null {
  const tokens = commandTokens(argv);
  const head = tokens[0];
  if (head === undefined) {
    // コマンド名なし(bare `maruhi` / オプションのみ)は gunshi のエントリ
    // コマンドが受ける(使い方の表示・未宣言オプションの診断)
    return null;
  }
  if (!Object.hasOwn(COMMAND_SPECS, head)) {
    // 未知のコマンドも effect 側へ渡す(第 3 段階 ④ — gunshi の subCommands は
    // 空になったので、CommandNotFound の診断はもう出ない)。root の
    // UnknownSubcommand が候補・一覧(ROOT_SPEC_KEY の subcommands)を出す
    return ROOT_SPEC_KEY;
  }
  const nested = tokens[1] === undefined ? null : `${head} ${tokens[1]}`;
  return nested !== null && Object.hasOwn(COMMAND_SPECS, nested) ? nested : head;
}

/**
 * 内部エラー(バグ)の報告と終了コード。**message は出さない** — 打たれた値を
 * 埋め込んだ文面でも到達しうるので、型の名前だけを添える(failure.ts の
 * internalErrorKind)。無言で飲まないための最後の網でもある。
 */
async function reportInternalError(
  report: (messages: readonly string[]) => Promise<void>,
  error: unknown,
): Promise<number> {
  await report([`内部エラー(${internalErrorKind(error)})`]);
  return 1;
}

/**
 * Runs the maruhi CLI against `argv` with the given service layer and
 * returns the process exit code (0 = success, 1 = failure, 2 = usage error).
 */
export async function runCli(
  argv: readonly string[],
  layer: Layer.Layer<CliServices>,
): Promise<number> {
  let exitCode = 0;

  /** 診断 1 件以上を stderr へ出す(gunshi 自身の描画は止めてある)。 */
  const reportUsageError = async (messages: readonly string[]): Promise<void> => {
    await Effect.runPromise(
      Effect.gen(function* () {
        const io = yield* CliIo;
        for (const message of messages) {
          yield* io.logError(`maruhi: ${message}`);
        }
      }).pipe(Effect.provide(layer)),
    );
  };

  // コマンド名が `--` の**後ろ**にある実行(`maruhi -- run printenv`)は、
  // どのコマンドへ振り分けるかを決めるより先に落とす。gunshi は `--` を跨いで
  // コマンドを解決するため、通すと「`--` の後ろの先頭 = コマンド名そのもの」が
  // 実行対象として渡る。移行先(effect/unstable/cli)は跨がないが、そちらでは
  // 「余分な引数です」としか言えない — 直し方(コマンド名を前に出す)を
  // 伝えられる位置はここだけなので、振り分けの手前に置く
  if (commandNameAfterTerminator(argv)) {
    await reportUsageError([TERMINATOR_BEFORE_COMMAND]);
    return 2;
  }

  const migrated = migratedCommandKey(argv);
  if (migrated !== null) {
    // コマンド本体の defect は runEffectCli の中(`Effect.exit` + reportFailure)
    // が拾う。ここで受けるのは層の構築や logError 自体の失敗 = reject だけだが、
    // bin.ts は runCli を await するだけなので、拾わないと maruhi の文面ではなく
    // Bun の unhandled rejection が出る。内部エラーの報告経路を 1 本に保つ
    try {
      return await runEffectCli(migrated, argv, layer);
    } catch (error) {
      return await reportInternalError(reportUsageError, error);
    }
  }

  const execute: Execute = async (ctx, program, options) => {
    // 書き方の検査はコマンド本体より前 = 通信・復号より前に置く。
    // `pull --show=false` のような「書いたことと逆」の実行を、値を復号して
    // から拒否しない(復号された平文をそもそも作らない)。
    //
    // コマンド固有の拒否を**先に**見る: そのオプションが操作にそもそも
    // 適用されないなら、綴りの助言(`--new-epoch` と書き直せ)を先に出しても
    // 次の実行でまた落ちる(`env create --new-epoch=false` の 2 度手間)
    // 検査の一覧は args.ts が持つ(ここで項目を転記すると、増やしたときに
    // 渡し忘れた検査が黙って死ぬ)
    const rejection = argsRejection(ctx, options);
    if (rejection !== null) {
      await reportUsageError([rejection]);
      // 引数の書き方の誤りは usage エラー(2)。gunshi の strict が落とす
      // 未宣言オプションと同じ終了コードで揃える
      exitCode = 2;
      return;
    }
    const handled = program.pipe(
      Effect.map((code) => (typeof code === "number" ? code : 0)),
      Effect.catch((error) =>
        Effect.gen(function* () {
          const io = yield* CliIo;
          const failure = toCliError(error);
          yield* io.logError(`maruhi: ${failure.message}`);
          // 引数の書き方の誤りは、コマンド本体が見つけた場合でも usage エラー
          // (2)。実行の失敗(1)と混ぜると、スクリプトが打ち間違いを
          // 「操作が失敗した」と読む
          return failure.usage === true ? 2 : 1;
        }),
      ),
      // defect(バグ)を usage エラー(2)に化けさせない: runPromise の
      // reject → gunshi 経由で外側 catch へ落ちると exit 2 になってしまう
      Effect.catchDefect((defect) =>
        Effect.gen(function* () {
          const io = yield* CliIo;
          // defect の message は出さない(打たれた値を埋め込んだ文面でも到達
          // しうる)。型の名前だけを添える — 移行先(effect-cli.ts の
          // reportFailure)と同じ形で、内部エラーの見え方を 1 つに保つ
          yield* io.logError(`maruhi: 内部エラー(${internalErrorKind(defect)})`);
          return 1;
        }),
      ),
      Effect.provide(layer),
    );
    exitCode = await Effect.runPromise(handled);
  };

  const subCommands = {};

  // コマンドの一覧は「gunshi に残っているもの + 移行済みのもの」。登録済みの
  // 表から導くのは変わらないが、移行済みのコマンドは gunshi の subCommands に
  // 居ないので、ここで合流させる — ヘルプの一覧と**打ち間違いの候補**の両方が
  // これを読む。合流させないと `maruhi pul` が「不明なコマンドです」の候補に
  // pull を出せず、実在するコマンドについて嘘をつく
  // (段は先頭だけ: `env create` は `env` として既に並んでいる)
  const migratedNames = [
    ...new Set(Object.keys(COMMAND_SPECS).map((key) => key.split(" ")[0] ?? key)),
  ].filter((name) => name !== "" && !Object.hasOwn(subCommands, name));
  const knownCommands: CommandTable = {
    ...subCommands,
    // 移行済みは引数表を持たない(gunshi の execute へは来ない)。候補の
    // 名前としてだけ並べる
    ...Object.fromEntries(migratedNames.map((name) => [name, {}])),
  };
  const commandNames = Object.keys(knownCommands);

  try {
    await cli([...argv], entryCommand(execute, commandNames), {
      name: "maruhi",
      version: CLI_VERSION,
      description: "maruhi — ディスクレス secrets 管理 CLI",
      // 未宣言のオプションを runner 実行前に検証エラーにする(既定は false =
      // 黙って無視)。`maruhi pull --shwo` が `--show` なしで実行される形と、
      // 位置引数の名前をオプションとして書いた形(`env create dev
      // --environment-id prod`= 値が捨てられる)を全コマンドで塞ぐ。
      // `--` の後ろ(`maruhi run -- cmd --flag`)は検査対象外
      strict: true,
      // gunshi 自身の描画(いずれも console.log = **stdout**)は止め、診断は
      // 下の catch から stderr へ 1 本化する。ヘッダ(バナー)は成功した実行
      // でも毎回出るため、`V=$(maruhi config get server)` が値ではなくバナーを
      // 捕まえていた — stdout はコマンドの出力だけにする
      renderValidationErrors: null,
      renderHeader: null,
      subCommands,
    });
  } catch (error) {
    // 引数検証・未知コマンドは usage エラー(2)。それ以外(コマンド定義の
    // 組み立てで throw した等のバグ)は 1 で報告する — 打ち間違いと区別できないと
    // 直しようがないうえ、無言で飲むことにもなる(CLAUDE.md)
    if (error instanceof AggregateError) {
      await reportUsageError(usageErrorMessages(error, argv, knownCommands));
      return 2;
    }
    return await reportInternalError(reportUsageError, error);
  }
  return exitCode;
}
