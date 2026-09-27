// Parts shared by build-binaries.ts / build-npm.ts / print-smoke-matrix.ts.

import { spawnSync } from "node:child_process";

/**
 * Single source of truth for release targets. Both binary generation
 * (build-binaries.ts) and release.yml's smoke matrix (print-smoke-matrix.ts →
 * fromJSON) are derived from here. Adding a target automatically gives it a
 * real-OS smoke — structurally prevents the shape where a duplicated table
 * forgets the smoke side and an artifact that only passed cross-compilation
 * gets published.
 *
 * runner is the GitHub-hosted runner label used for the smoke. darwin-x64 uses
 * macos-15-intel, the last Intel mac generation (retires 2027-08 — revisit this
 * then).
 */
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

/**
 * Canonical SemVer (no build metadata — `+` is not used in tags).
 * A loose `\d+`-based pattern would accept `01.2.3` and only get rejected at
 * npm publish after the GitHub Release exists, leaving Release and npm out of
 * sync. Apply the same check npm uses at the head of the gate (release.yml's
 * version-check has the same-shaped ERE).
 */
export const SEMVER_PATTERN =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?$/;

/** Runs a child process synchronously, distinguishing spawn failure, signal death, and non-zero exit. */
export function run(command: string, args: readonly string[], cwd: string): void {
  const result = spawnSync(command, [...args], { cwd, stdio: "inherit" });
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
