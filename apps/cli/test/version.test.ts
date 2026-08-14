// バージョンの単一の出所(apps/cli/package.json)の固定。
// リリースはタグ ↔ package.json の一致を release workflow が検査する前提なので、
// 「package.json の版がそのまま `--version` に出る」ことを回帰の砦にする。

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import packageJson from "../package.json";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));

describe("CLI のバージョン(単一の出所 = package.json)", () => {
  it("version はタグ照合・npm publish の前提となる SemVer である", () => {
    expect(packageJson.version).toMatch(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$/);
  });

  it("`maruhi --version` は package.json の version をそのまま出力する", () => {
    const result = spawnSync("bun", ["src/bin.ts", "--version"], {
      cwd: cliRoot,
      encoding: "utf8",
    });
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe(packageJson.version);
  });
});
