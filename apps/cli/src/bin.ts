#!/usr/bin/env bun
// `maruhi` / `mh` バイナリのエントリポイント(Bun ランタイム)。

import { runCli } from "./cli.ts";
import { liveLayer } from "./live.ts";

// Bun 以外(npm 配布物を Node.js で起動した場合)は入口で止める: ここを通すと
// keychain(Bun.secrets)や run(Bun.spawn)に触れた時点の ReferenceError になり、
// 「ランタイム違い」という原因が利用者に伝わらない
if (typeof globalThis.Bun === "undefined") {
  console.error(
    "maruhi CLI は Bun ランタイム上でのみ動作します(https://bun.sh)。" +
      "Bun を導入するか、GitHub Releases のコンパイル済みバイナリを利用してください。",
  );
  process.exit(1);
}

const exitCode = await runCli(process.argv.slice(2), liveLayer());
// exitCode 代入でなく明示 exit: キーチェーン操作のタイムアウト(live.ts)で
// 中断された Bun.secrets の pending なネイティブ呼び出しがイベントループを
// 生かし続け、プロセスが終了しないことを実測したため
process.exit(exitCode);
