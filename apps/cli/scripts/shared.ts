import { spawnSync } from "node:child_process";

export const TARGETS = [
  { bunTarget: "bun-linux-x64", name: "linux-x64", bin: "maruhi", runner: "ubuntu-latest" },
  { bunTarget: "bun-linux-arm64", name: "linux-arm64", bin: "maruhi", runner: "ubuntu-24.04-arm" },
  { bunTarget: "bun-darwin-x64", name: "darwin-x64", bin: "maruhi", runner: "macos-15-intel" },
  { bunTarget: "bun-darwin-arm64", name: "darwin-arm64", bin: "maruhi", runner: "macos-latest" },
  {
    bunTarget: "bun-windows-x64",
    name: "windows-x64",
    bin: "maruhi.exe",
    runner: "windows-latest",
  },
] as const;

export const SEMVER_PATTERN =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?$/;

export function run(
  command: string,
  args: readonly string[],
  cwd: string,
  env: NodeJS.ProcessEnv = process.env,
): void {
  const result = spawnSync(command, [...args], { cwd, env, stdio: "inherit" });
  if (result.error !== undefined) {
    throw new Error(`failed to spawn ${command}: ${result.error.message}`);
  }
  if (result.signal !== null) {
    throw new Error(`${command} ${args.join(" ")} died on signal ${result.signal}`);
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} exited with status ${result.status}`);
  }
}
