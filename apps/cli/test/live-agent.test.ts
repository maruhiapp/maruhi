// Pins `maruhi agent`'s production path (live.ts's runAgentSession —
// Bun.spawn and signal passthrough, plus agent.ts's teardown) with a real
// process. Since vitest runs under Node, `bun` launches bin.ts and we
// observe from outside (same trick as live-exec.test.ts). Interactive
// signal delivery is not checked — what is checked is "when the child
// exits, agent exits too, inherits the exit code, and the socket's
// directory is gone".

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

describeUnix("maruhi agent (live — a real process)", () => {
  it("agent listens only while the child lives, inherits its exit code, and removes the socket directory", () => {
    const configDir = scratchDir("maruhi-agent-live-cfg-");
    const runtimeDir = scratchDir("maruhi-agent-live-run-");
    // Child: prints the socket path to stdout, fetches status from inside
    // the session, exits with 7
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
    // status from inside the session reaches agent (it holds nothing yet)
    expect(result.stdout).toContain(`socket:      ${socketPath}`);
    expect(result.stdout).toContain("holding:     nothing yet");
    expect(result.stderr).toContain("Agent session started");
    // Once the child exits, neither socket nor directory remains
    expect(existsSync(socketPath)).toBe(false);
    expect(existsSync(join(socketPath, ".."))).toBe(false);
  });
});
