// `maruhi agent` の本番経路(live.ts の runAgentSession — Bun.spawn とシグナル
// の据え置き、agent.ts の後始末)を実プロセスで固定する。vitest は Node で
// 走るため、`bun` で bin.ts を起動して外から観測する(live-exec.test.ts と同じ
// 手口)。対話的なシグナル配送は検査しない — 検査するのは「子が終われば agent も
// 終わり、終了コードを引き継ぎ、ソケットのディレクトリが消える」こと。

import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

const BIN = join(import.meta.dirname, "..", "src", "bin.ts");

const describeUnix = platform() === "win32" ? describe.skip : describe;

let scratch: string[] = [];

afterEach(() => {
  for (const dir of scratch) {
    rmSync(dir, { recursive: true, force: true });
  }
  scratch = [];
});

function scratchDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  scratch.push(dir);
  return dir;
}

describeUnix("maruhi agent(live — 実プロセス)", () => {
  it("子の間だけ agent が聞き、終了コードを引き継ぎ、ソケットのディレクトリを消す", () => {
    const configDir = scratchDir("maruhi-agent-live-cfg-");
    const runtimeDir = scratchDir("maruhi-agent-live-run-");
    // 子: ソケットのパスを stdout に出し、セッションの中から status を取り、7 で終わる
    const script = [
      'printf "sock=%s\\n" "$MARUHI_AGENT_SOCK"',
      `bun "${BIN}" agent status`,
      "exit 7",
    ].join(" && ");
    const result = spawnSync("bun", [BIN, "agent", "--", "sh", "-c", script], {
      encoding: "utf8",
      timeout: 60_000,
      env: {
        ...process.env,
        MARUHI_CONFIG_DIR: configDir,
        XDG_RUNTIME_DIR: runtimeDir,
        MARUHI_AGENT_SOCK: "",
      },
    });
    expect(result.status, result.stderr).toBe(7);
    const socketPath = /^sock=(.+)$/m.exec(result.stdout)?.[1] ?? "";
    expect(socketPath.startsWith(`${runtimeDir}/maruhi-agent-`)).toBe(true);
    expect(socketPath.endsWith("/agent.sock")).toBe(true);
    // セッションの中の status は agent に届いている(まだ何も持っていない)
    expect(result.stdout).toContain(`socket:      ${socketPath}`);
    expect(result.stdout).toContain("holding:     nothing yet");
    expect(result.stderr).toContain("Agent session started");
    // 子が終わればソケットもディレクトリも残らない
    expect(existsSync(socketPath)).toBe(false);
    expect(existsSync(join(socketPath, ".."))).toBe(false);
  });
});
