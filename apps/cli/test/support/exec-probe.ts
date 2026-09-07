// 本番 ProcessRunner(live.ts — Bun.spawn)の `exec` を実プロセスで確かめる
// プローブ。vitest は Node で走り `Bun` が無いので、live-exec.test.ts がこの
// スクリプトを `bun` で起動し、結果 JSON を stdout から読む。
//
// 検査対象: 値が stdin に**丸ごと**届く(16 KiB — Vercel の上限ぶん)、子の環境に
// テレメトリ off の変数が入り MARUHI_* は入らない、出力が捕捉される(親の
// stdout に流れない)、非 0 の終了コードが返る、起動できないコマンドは型付き
// エラー。子は sh の 1 行(値を stdin から読み、長さと環境の有無だけを報告する —
// 値そのものは出力しない)。

import { Effect, Redacted } from "effect";

import { liveLayer } from "../../src/live.ts";
import { ProcessRunner } from "../../src/run.ts";

const value = "v".repeat(16 * 1024);
// 子に渡してはならない名前空間(deepsec S6)を親に置いておく
process.env["MARUHI_TOKEN"] = "maruhi_pat_probe_dummy";
process.env["MARUHI_TOKEN_ORIGIN"] = "https://probe.invalid";

const script =
  'input=$(cat); printf "len=%s telemetry=%s maruhi=%s\\n" "${#input}" "${WRANGLER_SEND_METRICS:-unset}" "${MARUHI_TOKEN:-unset}"; echo "to-stderr" >&2; exit 3';

const program = Effect.gen(function* () {
  const runner = yield* ProcessRunner;
  const outcome = yield* runner.exec({
    command: ["sh", "-c", script],
    cwd: process.cwd(),
    extraEnv: { WRANGLER_SEND_METRICS: "false" },
    stdin: Redacted.make(new TextEncoder().encode(value), { label: "sync-stdin" }),
  });
  const missing = yield* runner
    .exec({
      command: ["maruhi-probe-not-installed-9f3c"],
      cwd: process.cwd(),
      extraEnv: {},
      stdin: Redacted.make(new Uint8Array(0), { label: "sync-stdin" }),
    })
    .pipe(
      Effect.map(() => "unexpectedly started"),
      Effect.catch((error) => Effect.succeed(error.message)),
    );
  const badCwd = yield* runner
    .exec({
      command: ["sh", "-c", "true"],
      cwd: "/nonexistent-maruhi-probe-dir",
      extraEnv: {},
      stdin: Redacted.make(new Uint8Array(0), { label: "sync-stdin" }),
    })
    .pipe(
      Effect.map(() => "unexpectedly started"),
      Effect.catch((error) => Effect.succeed(error.message)),
    );
  return { exitCode: outcome.exitCode, output: outcome.output, missing, badCwd };
});

const result = await Effect.runPromise(program.pipe(Effect.provide(liveLayer())));
// stdout はこの JSON だけ(子の出力が混ざっていないことも検査対象)
console.log(JSON.stringify(result));
