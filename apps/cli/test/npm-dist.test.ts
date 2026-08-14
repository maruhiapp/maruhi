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
      // spawnSync はイベントループを塞ぐため vitest の hook タイムアウト(下の
      // 30s)は同期呼び出しを中断できない。hook 上限より手前で子を殺す
      timeout: 25_000,
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
      timeout: 10_000,
    });
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe(packageJson.version);
  });

  it("バンドルに workspace マニフェスト全体を埋め込まない", async () => {
    // cli.ts の package.json import は現状 tree-shake され version だけが残る
    // (named / default とも実測)。これはバンドラ挙動であり保証ではないため、
    // 退行すると scripts・依存ピン等の開発用マニフェスト全体が npm 配布物と
    // 全バイナリへ複製される — その成果物側の性質をここで固定する
    const bundle = await readFile(join(outDir, "bin.js"), "utf8");
    expect(bundle).toContain(packageJson.version);
    expect(bundle).not.toContain('"devDependencies"');
  });

  it("Node.js で起動すると Bun 必須の案内で exit 1(深部の ReferenceError にしない)", () => {
    const result = spawnSync("node", [join(outDir, "bin.js"), "--version"], {
      encoding: "utf8",
      timeout: 10_000,
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Bun");
    expect(result.stderr).not.toContain("ReferenceError");
  });
});
