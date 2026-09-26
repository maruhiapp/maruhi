// Pins the shape of the release-target table (TARGETS in
// scripts/shared.ts). It's the single source for binary generation and
// release.yml's smoke matrix, so a tear in the table directly means a
// missed build, an unverified artifact getting published, or a matrix
// interpretation error.

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { TARGETS } from "../scripts/shared.ts";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));

describe("the release-target table (TARGETS)", () => {
  it("contains the current 5 targets, names are unique, and runner / bin shapes are right", () => {
    const names = TARGETS.map((t) => t.name);
    for (const required of [
      "linux-x64",
      "linux-arm64",
      "darwin-x64",
      "darwin-arm64",
      "windows-x64",
    ]) {
      expect(names).toContain(required);
    }
    expect(new Set(names).size).toBe(names.length);
    for (const target of TARGETS) {
      expect(target.bunTarget).toBe(`bun-${target.name}`);
      expect(target.runner).not.toBe("");
      // .exe on Windows only (adding it elsewhere breaks the smoke run
      // path)
      expect(target.bin).toBe(target.name.startsWith("windows") ? "maruhi.exe" : "maruhi");
    }
  });

  it("the smoke-matrix derivation (print-smoke-matrix) emits every target in GH-matrix shape", () => {
    const result = spawnSync("bun", ["scripts/print-smoke-matrix.ts"], {
      cwd: cliRoot,
      encoding: "utf8",
      timeout: 10_000,
    });
    expect(result.status).toBe(0);
    const matrix = JSON.parse(result.stdout) as readonly {
      target: string;
      runner: string;
      bin: string;
    }[];
    expect(matrix.map((entry) => entry.target)).toEqual(TARGETS.map((t) => t.name));
    for (const entry of matrix) {
      expect(Object.keys(entry).toSorted()).toEqual(["bin", "runner", "target"]);
    }
  });
});
