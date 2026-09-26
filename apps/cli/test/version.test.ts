// Pins the version's single source (apps/cli/package.json). Releases are
// premised on the release workflow checking tag ↔ package.json agreement,
// so the regression wall is "the package.json version shows up verbatim
// in `--version`".

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import packageJson from "../package.json";
import { SEMVER_PATTERN } from "../scripts/shared.ts";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));

describe("the CLI version (single source = package.json)", () => {
  it("version is SemVer, the precondition for tag matching and npm publish", () => {
    expect(packageJson.version).toMatch(SEMVER_PATTERN);
  });

  it("the SemVer check doesn't pass shapes npm rejects (leading zeros etc.)", () => {
    // A lax check would first get bounced at npm publish — after the
    // GitHub Release already exists — leaving Release and npm disagreeing
    // (release.yml's version-check is the same shape)
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
      // spawnSync blocks the event loop, so vitest's timeout can't fire.
      // On a hang, kill the child and fail the test
      timeout: 10_000,
    });
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe(packageJson.version);
  });
});
