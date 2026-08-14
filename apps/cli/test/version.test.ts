// バージョンの単一の出所(apps/cli/package.json)の固定。
// リリースはタグ ↔ package.json の一致を release workflow が検査する前提なので、
// 「package.json の版がそのまま `--version` に出る」ことを回帰の砦にする。

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import packageJson from "../package.json";
import { SEMVER_PATTERN } from "../scripts/shared.ts";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));

describe("CLI のバージョン(単一の出所 = package.json)", () => {
  it("version はタグ照合・npm publish の前提となる SemVer である", () => {
    expect(packageJson.version).toMatch(SEMVER_PATTERN);
  });

  it("SemVer 判定は npm が拒む形(先頭ゼロ等)を通さない", () => {
    // 緩い判定だと GitHub Release 作成後の npm publish で初めて弾かれ、
    // Release と npm が食い違う(release.yml の version-check も同型)
    for (const bad of ["01.2.3", "1.2", "1.2.3-", "1.2.3-01", "v1.2.3"]) {
      expect(bad).not.toMatch(SEMVER_PATTERN);
    }
    for (const good of ["0.1.0", "0.1.0-rc.1", "1.2.3-beta.11"]) {
      expect(good).toMatch(SEMVER_PATTERN);
    }
  });

  it("`maruhi --version` は package.json の version をそのまま出力する", () => {
    const result = spawnSync("bun", ["src/bin.ts", "--version"], {
      cwd: cliRoot,
      encoding: "utf8",
      // spawnSync はイベントループを塞ぐため vitest のタイムアウトが効かない。
      // hang 時は子を殺してテストを失敗させる
      timeout: 10_000,
    });
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe(packageJson.version);
  });
});
