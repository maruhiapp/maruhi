// npm 配布物(scripts/build-npm.ts が組むステージング)の性質の固定。
// バンドル生成に数秒かかるため、一度だけ組んで複数の性質を検査する。

import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import packageJson from "../package.json";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));

describe("npm 配布物のステージング(build-npm)", () => {
  let outDir: string;

  beforeAll(() => {
    outDir = mkdtempSync(join(tmpdir(), "maruhi-npm-dist-"));
    const result = spawnSync("bun", ["scripts/build-npm.ts", outDir], {
      cwd: cliRoot,
      encoding: "utf8",
    });
    if (result.status !== 0) {
      throw new Error(`build-npm.ts が失敗: ${result.stderr}`);
    }
  }, 30_000);

  afterAll(async () => {
    await rm(outDir, { recursive: true, force: true });
  });

  it("package.json: 公開名 maruhi / 版は workspace と一致 / bin は maruhi と mh", async () => {
    const manifest = JSON.parse(await readFile(join(outDir, "package.json"), "utf8")) as {
      name: string;
      version: string;
      private?: boolean;
      bin: Record<string, string>;
      dependencies?: Record<string, string>;
      engines?: Record<string, string>;
    };
    expect(manifest.name).toBe("maruhi");
    expect(manifest.version).toBe(packageJson.version);
    expect(manifest.private).toBeUndefined();
    expect(Object.keys(manifest.bin).toSorted()).toEqual(["maruhi", "mh"]);
    // workspace 依存と effect beta はバンドルに畳む(ADR-0015)。依存が復活すると
    // 未 publish の @maruhi/* を指して壊れるため、依存なしを固定する
    expect(manifest.dependencies).toBeUndefined();
    expect(manifest.engines?.["bun"]).toMatch(/^>=\d/);
  });

  it("バンドルは Bun で動き、--version が workspace の版を出す", () => {
    const result = spawnSync("bun", [join(outDir, "bin.js"), "--version"], {
      encoding: "utf8",
    });
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe(packageJson.version);
  });

  it("Node.js で起動すると Bun 必須の案内で exit 1(深部の ReferenceError にしない)", () => {
    const result = spawnSync("node", [join(outDir, "bin.js"), "--version"], {
      encoding: "utf8",
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Bun");
    expect(result.stderr).not.toContain("ReferenceError");
  });
});
