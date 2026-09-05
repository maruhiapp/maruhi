// maruhi CLI のエントリ: 引数層は `effect/unstable/cli`(effect-cli.ts)。
//
// ADR-0016 第 3 段階(最終)で gunshi は完全に廃止した(決定 1)。runCli に
// 残るのは (1) `--` より前にコマンド名が無い実行の専用診断(effect 側は
// 「余分な引数」としか言えず、直し方を伝えられない)、(2) 診断の宛先
// (コマンド段)の解決、(3) 内部エラーの最終網、の 3 つだけ。
//
// 値の入力は stdin(argv に平文値を載せない)、値の表示は pull --show のみで、
// 人間の対話端末以外では拒否する(agent-gate.ts)。`maruhi run` は許可される。

import { Effect, type Layer } from "effect";

import type { CliServices } from "./context.ts";
import { COMMAND_SPECS, ROOT_SPEC_KEY, runEffectCli } from "./effect-cli.ts";
import { internalErrorKind } from "./failure.ts";
import { logFailure } from "./notice.ts";

export type { CliServices } from "./context.ts";

/**
 * コマンド名が `--` の**後ろ**にある実行の文面。effect/unstable/cli は `--` を
 * 跨いでコマンドを解決しない(12 形の #7)が、その診断は「余分な引数です」に
 * しかならず、直し方(コマンド名を前に出す)を伝えられない。専用の文面を
 * 出せる位置は振り分けの手前のここだけ。
 */
const TERMINATOR_BEFORE_COMMAND =
  "Write the command name before `--` (everything after `--` is passed through as arguments)";

/**
 * `--` より前の位置引数(コマンド名の候補)を argv から集める。
 *
 * gunshi 廃止(決定 1)に伴い、gunshi の `parseArgs` に頼っていた走査
 * (旧 args.ts の commandTokens / commandNameAfterTerminator)を最小の自前
 * 字句に置き換えた。これは決定 2 が禁じる「引数の**検査**の走査」ではなく
 * **振り分けの材料**で、宣言には載らない。`-` で始まるトークンはオプション
 * (またはその綴りの誤り)、それ以外を位置引数として拾う。値を取るオプションの
 * 値も位置引数として並ぶ(gunshi の parseArgs も同じ — 引数表を知らない
 * 字句だけの走査)が、利用側は「先頭の非空トークン」と「`--` より前に
 * 位置引数があるか」しか見ないので、effect 側の解決と食い違わない。
 */
function positionalTokens(argv: readonly string[]): {
  readonly beforeTerminator: readonly string[];
  readonly afterTerminatorHasTokens: boolean;
} {
  const before: string[] = [];
  let terminated = false;
  let after = false;
  for (const token of argv) {
    if (!terminated && token === "--") {
      terminated = true;
      continue;
    }
    if (terminated) {
      after = after || token.length > 0;
      continue;
    }
    if (token === "" || !token.startsWith("-")) {
      before.push(token);
    }
  }
  return { beforeTerminator: before, afterTerminatorHasTokens: after };
}

/**
 * `effect/unstable/cli` へ渡す診断の宛先(解決済みのコマンド段)。
 *
 * 先頭のコマンド名で振り分け、2 語目が既知のサブコマンドなら診断の宛先を
 * その段(`env rotate`)まで確定する。未知のコマンド・コマンド名なしは
 * root(ROOT_SPEC_KEY)— 診断は effect 側の UnknownSubcommand /
 * UnrecognizedOption が受け持つ。空のトークンはコマンド名として解決しない
 * (effect 側も解決しない)。段の一覧は COMMAND_SPECS から引く(手書きの
 * 写しを持たない)。
 */
function commandKeyOf(tokens: readonly string[]): string {
  const named = tokens.filter((token) => token !== "");
  const head = named[0];
  if (head === undefined || !Object.hasOwn(COMMAND_SPECS, head)) {
    return ROOT_SPEC_KEY;
  }
  const nested = named[1] === undefined ? null : `${head} ${named[1]}`;
  return nested !== null && Object.hasOwn(COMMAND_SPECS, nested) ? nested : head;
}

/**
 * Runs the maruhi CLI against `argv` with the given service layer and
 * returns the process exit code (0 = success, 1 = failure, 2 = usage error).
 */
export async function runCli(
  argv: readonly string[],
  layer: Layer.Layer<CliServices>,
): Promise<number> {
  /** 診断 1 件以上を stderr へ出す(runEffectCli の外側の最終網)。 */
  const reportError = async (messages: readonly string[]): Promise<void> => {
    await Effect.runPromise(
      Effect.forEach(messages, (message) => logFailure(message), { discard: true }).pipe(
        Effect.provide(layer),
      ),
    );
  };

  // コマンド名が `--` の**後ろ**にある実行(`maruhi -- run printenv`)は、
  // どのコマンドへ振り分けるかを決めるより先に落とす(上記の専用診断)。
  // 空のトークンはコマンド名として解決されない(gunshi も読み飛ばしていた)
  // ので、`maruhi "" -- run` も同じ形として扱う
  const tokens = positionalTokens(argv);
  if (tokens.beforeTerminator.every((token) => token === "") && tokens.afterTerminatorHasTokens) {
    await reportError([TERMINATOR_BEFORE_COMMAND]);
    return 2;
  }

  // コマンド本体の defect は runEffectCli の中(`Effect.exit` + reportFailure)
  // が拾う。ここで受けるのは層の構築や logError 自体の失敗 = reject だけだが、
  // bin.ts は runCli を await するだけなので、拾わないと maruhi の文面ではなく
  // Bun の unhandled rejection が出る。message は出さない(打たれた値を
  // 埋め込んだ文面でも到達しうる)— 型の名前だけを添える(failure.ts)
  try {
    return await runEffectCli(commandKeyOf(tokens.beforeTerminator), argv, layer);
  } catch (error) {
    await reportError([`internal error (${internalErrorKind(error)})`]);
    return 1;
  }
}
