// maruhi の終了コード規約を **`runMain` の teardown として**表す。
//
// 規約: 0 = 成功 / 1 = 実行の失敗 / **2 = 書き方の誤り**。スクリプトが打ち間違いを
// 「操作が失敗した」と読まないために、この 3 値は崩せない。
//
// 実行の失敗は `Runtime.errorExitCode` をエラー型自身が持つので写像表は要らない。
// 唯一の例外が `ShowHelp`(レビュー指摘): 上流は
// `ShowHelp[Runtime.errorExitCode] = this.errors.length ? 1 : 0` を宣言しており、
// **書き方の誤りが exit 1 になる**。上流が用意しているフックは
// `makeRunMain({ teardown })` だけ(`CliConfig` は builtIns しか持たない)なので、
// ここで読み替える。ハーネス側で終了コードを手計算すると、本番の起動経路
// (`BunRuntime.runMain`)を検査できなくなる — スパイクも本番もこの teardown を通す。

import { Cause, Exit, Runtime } from "effect";
import { CliError } from "effect/unstable/cli";

/** 書き方の誤り。実行の失敗(1)と区別できないと打ち間違いを直せない。 */
const USAGE_EXIT_CODE = 2;

/**
 * Teardown that maps CLI usage errors to exit code 2 and defers everything else
 * to {@link Runtime.defaultTeardown}.
 *
 * 本番は `BunRuntime.runMain(program, { teardown: maruhiTeardown })` で使う。
 */
export const maruhiTeardown: Runtime.Teardown = <E, A>(
  exit: Exit.Exit<E, A>,
  onExit: (code: number) => void,
): void => {
  if (Exit.isFailure(exit)) {
    const failure: unknown = Cause.squash(exit.cause);
    // errors が空 = `--help` / `--version`(誤りではない)。上流の 0 に従う
    if (failure instanceof CliError.ShowHelp && failure.errors.length > 0) {
      onExit(USAGE_EXIT_CODE);
      return;
    }
  }
  Runtime.defaultTeardown(exit, onExit);
};
