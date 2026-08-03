#!/usr/bin/env bun
// `maruhi` / `mh` バイナリのエントリポイント(Bun ランタイム)。

import { runCli } from "./cli.ts";
import { liveLayer } from "./live.ts";

process.exitCode = await runCli(process.argv.slice(2), liveLayer());
