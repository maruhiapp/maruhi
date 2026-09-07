// 本番 ProcessRunner の `exec`(live.ts — `maruhi sync` の exec ドライバの
// 子プロセス境界)を実プロセスで固定する。vitest は Node で走るため、Bun.spawn を
// 使う実装は `bun` で起動したプローブ(support/exec-probe.ts)経由で検査する。

import { spawnSync } from "node:child_process";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const PROBE = join(import.meta.dirname, "support", "exec-probe.ts");

interface ProbeResult {
  readonly exitCode: number;
  readonly output: string;
  readonly missing: string;
  readonly badCwd: string;
}

describe("ProcessRunner.exec(live — Bun.spawn)", () => {
  it("値は stdin に丸ごと届き、子の環境にテレメトリ off が入り MARUHI_* は入らず、出力は捕捉され、終了コードが返る", () => {
    const result = spawnSync("bun", [PROBE], {
      encoding: "utf8",
      // spawnSync はイベントループを塞ぐため vitest の hook タイムアウトより短く
      timeout: 60_000,
    });
    expect(result.status, result.stderr).toBe(0);
    // 親の stdout はプローブの JSON 1 行だけ(子の出力が素通りしていない)
    const lines = result.stdout.trim().split("\n");
    expect(lines).toHaveLength(1);
    const probe = JSON.parse(lines[0] ?? "") as ProbeResult;
    expect(probe.exitCode).toBe(3);
    expect(probe.output).toContain("len=16384 telemetry=false maruhi=unset");
    // 出力は切らずに丸ごと返る(切るのは伏せた後 — sync-exec.ts)
    expect(probe.output).toContain("x".repeat(70_000));
    expect(probe.output).toContain("to-stderr");
    // 未導入のコマンドは型付きエラー(取りに行かない)
    expect(probe.missing).toContain("Cannot start maruhi-probe-not-installed-9f3c");
    expect(probe.missing).toContain("maruhi never downloads a vendor CLI");
    expect(probe.missing).toContain("(ENOENT)");
    // cwd の不在は実行体の不在と区別して名指しする(Bugbot 指摘)
    expect(probe.badCwd).toContain(
      "the target's working directory does not exist or is not a directory (/nonexistent-maruhi-probe-dir)",
    );
  });
});
