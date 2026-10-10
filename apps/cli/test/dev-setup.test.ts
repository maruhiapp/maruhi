// Pins "the dev-environment setup runs no toolchain fetched without a pinned
// digest". The Claude Code on the web SessionStart hook installs Bun through
// scripts/install-bun.sh — the script and pin CI uses (workflow-caches.test.ts
// pins its version and SHA-256s) — and pnpm only through corepack's check of
// the sha512 in .deepsec/package.json. The script is also run here offline
// against a tampered download, to show it fails closed with nothing installed.

import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));
const read = (path: string): string => readFileSync(join(repoRoot, path), "utf8");

describe("SessionStart hook (.claude/hooks/session-start.sh)", () => {
  const hook = read(".claude/hooks/session-start.sh");

  it("installs Bun only through scripts/install-bun.sh", () => {
    expect(hook).toContain("bash scripts/install-bun.sh");
    expect(hook).not.toMatch(/bun\.sh\/install/);
  });

  it("fetches nothing itself: no curl, wget, piped shell, bunx, npx, dlx or Playwright download", () => {
    expect(hook).not.toMatch(/\b(curl|wget|bunx|npx|dlx)\b|\|\s*(ba)?sh\b|playwright install/);
  });

  it("runs pnpm through corepack when it exists, and a preinstalled pnpm without its self-switch", () => {
    const corepack = hook.indexOf("command -v corepack");
    const pnpm = hook.indexOf("command -v pnpm");
    expect(corepack).toBeGreaterThan(-1);
    expect(pnpm).toBeGreaterThan(corepack);
    expect(hook).toContain("corepack pnpm install --frozen-lockfile");
    expect(hook).toContain(
      "pnpm install --frozen-lockfile --config.manage-package-manager-versions=false",
    );
  });

  it(".deepsec pins pnpm with the sha512 corepack checks", () => {
    const manifest = JSON.parse(read(".deepsec/package.json")) as { packageManager?: string };
    expect(manifest.packageManager).toMatch(/^pnpm@\d+\.\d+\.\d+\+sha512\.[0-9a-f]{128}$/);
  });
});

describe.runIf(process.platform === "linux" && process.arch === "x64")(
  "scripts/install-bun.sh fails closed",
  () => {
    /** A copy of the script in a scratch repository, with a curl that serves a tampered zip. */
    function sandbox(bunVersion: string) {
      const root = mkdtempSync(join(tmpdir(), "install-bun-"));
      const repo = join(root, "repo");
      const home = join(root, "home");
      const bin = join(root, "bin");
      for (const dir of [join(repo, "scripts"), home, bin]) mkdirSync(dir, { recursive: true });
      copyFileSync(join(repoRoot, "scripts/install-bun.sh"), join(repo, "scripts/install-bun.sh"));
      writeFileSync(join(repo, ".bun-version"), `${bunVersion}\n`);
      const curlLog = join(root, "curl.log");
      writeFileSync(
        join(bin, "curl"),
        [
          "#!/bin/sh",
          `echo "$*" >> '${curlLog}'`,
          'while [ $# -gt 0 ]; do [ "$1" = --output ] && printf tampered > "$2"; shift; done',
          "",
        ].join("\n"),
      );
      chmodSync(join(bin, "curl"), 0o755);
      const result = spawnSync("bash", [join(repo, "scripts/install-bun.sh")], {
        encoding: "utf8",
        timeout: 30_000,
        env: { ...process.env, HOME: home, PATH: `${bin}:${process.env["PATH"] ?? ""}` },
      });
      const curlCalls = existsSync(curlLog) ? readFileSync(curlLog, "utf8") : "";
      const installed = existsSync(join(home, ".bun"));
      rmSync(root, { recursive: true, force: true });
      return { result, curlCalls, installed };
    }

    const pinned = read(".bun-version").trim();

    it("refuses a download that does not match the pinned SHA-256, installing nothing", () => {
      const { result, curlCalls, installed } = sandbox(pinned);
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain("did NOT match");
      expect(curlCalls).toMatch(
        new RegExp(
          `https://github\\.com/oven-sh/bun/releases/download/bun-v${pinned}/bun-linux-x64`,
        ),
      );
      expect(installed).toBe(false);
    });

    it("refuses a .bun-version the script does not pin, before downloading", () => {
      const { result, curlCalls, installed } = sandbox("0.0.1");
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(".bun-version is 0.0.1 but scripts/install-bun.sh pins");
      expect(curlCalls).toBe("");
      expect(installed).toBe(false);
    });
  },
);
