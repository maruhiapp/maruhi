// Audit for scripts/test-suite.mjs, the resolver the root `test:*`
// scripts delegate to. The resolver expands the root vitest.config.ts
// `projects:` list itself and assigns every discovered project to a
// suite by path rule — the failure mode it exists for is a project
// landing in no suite (a static `--project` list would skip it
// silently). This test cross-checks the partition against vitest's own
// resolution of the same config: the suite-assigned names and the
// project names `vitest list` reports must be exactly the same set.

import { spawnSync } from "node:child_process";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const ROOT = join(import.meta.dirname, "../../..");

// The audit spawns `vitest list` as a nested invocation; keep vitest's
// own markers out of its environment.
const env = { ...process.env };
for (const key of Object.keys(env)) {
  if (key.startsWith("VITEST")) delete env[key];
}

function run(args: string[], timeout = 30_000) {
  return spawnSync("bun", args, {
    cwd: ROOT,
    encoding: "utf8",
    timeout,
    env,
  });
}

describe("the test-suite resolver's partition of vitest projects", () => {
  it("assigns every project vitest resolves to exactly one suite", { timeout: 180_000 }, () => {
    const list = run(["scripts/test-suite.mjs", "list"]);
    expect(list.status, list.stderr).toBe(0);
    const partition = JSON.parse(list.stdout) as Record<string, string[]>;
    expect(Object.keys(partition).toSorted()).toEqual(["app-unit", "cli", "packages", "server"]);

    // vitest's own resolution of the same root config — the
    // independent source of truth for the project-name set.
    const vitest = run(["x", "vitest", "list", "--filesOnly"], 120_000);
    expect(vitest.status, vitest.stderr.slice(-2000)).toBe(0);
    const resolved = [
      ...new Set([...vitest.stdout.matchAll(/^\[([^\]]+)\]/gm)].map((m) => m[1])),
    ].toSorted();

    const assigned = Object.values(partition).flat();
    expect(new Set(assigned).size, "suites must be disjoint").toBe(assigned.length);
    for (const [suite, members] of Object.entries(partition)) {
      expect(members.length, `suite ${suite} must not be empty`).toBeGreaterThan(0);
    }
    expect([...assigned].toSorted()).toEqual(resolved);
  });

  it("maps paths by rule and hard-fails anything unmapped", () => {
    const cases: Array<[string, string | null]> = [
      ["packages/newlib/vitest.config.ts", "packages"],
      ["apps/cli/vitest.config.ts", "cli"],
      ["apps/server/vitest.config.ts", "server"],
      ["apps/web/vitest.unit.config.ts", "app-unit"],
      // An app's non-unit config (the web e2e config) has no suite by
      // design — adding one to `projects:` must fail, not be skipped.
      ["apps/web/vitest.config.ts", null],
      // A config outside every known area likewise has no suite.
      ["libs/foo/vitest.config.ts", null],
    ];
    for (const [path, expected] of cases) {
      const probe = run(["scripts/test-suite.mjs", "probe", path]);
      if (expected === null) {
        expect(probe.status, `${path} must fail`).toBe(1);
        expect(probe.stderr).toContain("matches no test-suite rule");
      } else {
        expect(probe.status, `${path}: ${probe.stderr}`).toBe(0);
        expect(probe.stdout.trim()).toBe(expected);
      }
    }
  });
});
