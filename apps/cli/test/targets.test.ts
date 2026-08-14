// リリース対象表(scripts/shared.ts の TARGETS)の形の固定。
// バイナリ生成と release.yml の smoke matrix の単一の出所なので、表の破れは
// ビルド漏れ・未検証成果物の公開・matrix の解釈エラーに直結する。

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { TARGETS } from "../scripts/shared.ts";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));

describe("リリース対象表(TARGETS)", () => {
  it("現行 5 対象を含み、名前は一意、runner / bin の形が正しい", () => {
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
      // Windows のみ .exe(それ以外に付くと smoke の実行パスが壊れる)
      expect(target.bin).toBe(target.name.startsWith("windows") ? "maruhi.exe" : "maruhi");
    }
  });

  it("smoke matrix の導出(print-smoke-matrix)は全対象を GH matrix の形で出す", () => {
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
