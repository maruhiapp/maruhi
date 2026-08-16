// maruhi の終了コード規約を **`runMain` の teardown として**表す(ADR-0016 決定 4)。
//
// 規約: 0 = 成功 / 1 = 実行の失敗 / **2 = 書き方の誤り**。スクリプトが打ち間違いを
// 「操作が失敗した」と読まないために、この 3 値は崩せない。
//
// 実行の失敗は `Runtime.errorExitCode` をエラー型自身が持つ(errors.ts の
// `CliError` が usage の有無で 2 / 1 を返す)ので写像表は要らない。
// 唯一の例外が `ShowHelp`: 上流は
// `ShowHelp[Runtime.errorExitCode] = this.errors.length ? 1 : 0` を宣言しており、
// **書き方の誤りが exit 1 になる**。上流が用意しているフックは
// `makeRunMain({ teardown })` だけ(`CliConfig` は builtIns しか持たない)なので、
// ここで読み替える。ハーネス側で終了コードを手計算すると、本番の起動経路を
// 検査できなくなる — テストも本番も cli.ts の 1 経路でこの teardown を通す。

import { Cause, Exit, Runtime } from "effect";
import { CliError } from "effect/unstable/cli";

/** 書き方の誤り。実行の失敗(1)と区別できないと打ち間違いを直せない。 */
const USAGE_EXIT_CODE = 2;

/**
 * Teardown that maps CLI usage errors to exit code 2 and defers everything else
 * to {@link Runtime.defaultTeardown}.
 *
 * `(exit, onExit) => void` なので `BunRuntime.runMain({ teardown })` へ渡す形でも、
 * `Effect.exit` の結果へ直接適用する形でも同じ判定になる(cli.ts は後者。
 * bin.ts の明示 `process.exit` を保つため — キーチェーン操作のタイムアウトで
 * 中断された `Bun.secrets` の pending なネイティブ呼び出しがイベントループを
 * 生かし続け、プロセスが終了しないことを実測している)。
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
