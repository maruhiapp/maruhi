#!/usr/bin/env bun
// `maruhi` / `mh` バイナリのエントリポイント(Bun ランタイム)。

// ランタイム検査は import ホイストより先に効かせる必要があるため、
// 先頭の副作用 import で行う(runtime-guard.ts)
import "./runtime-guard.ts";
import { runCli } from "./cli.ts";
import { liveLayer } from "./live.ts";

const exitCode = await runCli(process.argv.slice(2), liveLayer());
// exitCode 代入でなく明示 exit: キーチェーン操作のタイムアウト(live.ts)で
// 中断された Bun.secrets の pending なネイティブ呼び出しがイベントループを
// 生かし続け、プロセスが終了しないことを実測したため
process.exit(exitCode);
