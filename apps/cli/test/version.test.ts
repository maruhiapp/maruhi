import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vite-plus/test";

import packageJson from "../package.json";
import { SEMVER_PATTERN } from "../scripts/shared.ts";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));

describe("the CLI version (single source = package.json)", () => {
  it("version is SemVer, the precondition for tag matching and npm publish", () => {
    expect(packageJson.version).toMatch(SEMVER_PATTERN);
  });

  it("the SemVer check doesn't pass shapes npm rejects (leading zeros etc.)", () => {
    for (const bad of ["01.2.3", "1.2", "1.2.3-", "1.2.3-01", "v1.2.3"]) {
      expect(bad).not.toMatch(SEMVER_PATTERN);
    }
    for (const good of ["0.1.0", "0.1.0-rc.1", "1.2.3-beta.11"]) {
      expect(good).toMatch(SEMVER_PATTERN);
    }
  });

  it("`maruhi --version` prints package.json's version verbatim", () => {
    const result = spawnSync("bun", ["src/bin.ts", "--version"], {
      cwd: cliRoot,
      encoding: "utf8",
      timeout: 10_000,
    });
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe(packageJson.version);
  });
});
