import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

import packageJson from "../package.json";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));

const SERVER_FROM_DOTENV = "https://from-dotenv.invalid";
const PRELOAD_EXIT = 97;

describe("npm distribution staging (build-npm)", () => {
  let outDir: string;
  let fixtureDir: string;
  let workDir: string;
  let transpilerCacheDir: string;
  let runEnv: NodeJS.ProcessEnv;

  beforeAll(() => {
    fixtureDir = mkdtempSync(join(tmpdir(), "maruhi-npm-dist-run-"));
    const dotenvConfigDir = join(fixtureDir, "dotenv-config");
    mkdirSync(dotenvConfigDir);
    writeFileSync(
      join(dotenvConfigDir, "config.json"),
      `${JSON.stringify({ server: SERVER_FROM_DOTENV })}\n`,
    );
    mkdirSync(join(fixtureDir, "xdg"));
    workDir = join(fixtureDir, "work");
    mkdirSync(workDir);
    writeFileSync(join(workDir, ".env"), `MARUHI_CONFIG_DIR=${dotenvConfigDir}\n`);
    writeFileSync(join(workDir, "bunfig.toml"), 'preload = ["./preload.ts"]\n');
    writeFileSync(join(workDir, "preload.ts"), `process.exit(${PRELOAD_EXIT});\n`);
    transpilerCacheDir = join(fixtureDir, "transpiler-cache");
    mkdirSync(transpilerCacheDir);
    runEnv = {
      ...process.env,
      XDG_CONFIG_HOME: join(fixtureDir, "xdg"),
      BUN_RUNTIME_TRANSPILER_CACHE_PATH: transpilerCacheDir,
    };
    delete runEnv["MARUHI_CONFIG_DIR"];

    outDir = mkdtempSync(join(tmpdir(), "maruhi-npm-dist-"));
    const result = spawnSync("bun", ["scripts/build-npm.ts", outDir], {
      cwd: cliRoot,
      encoding: "utf8",
      timeout: 25_000,
    });
    if (result.status !== 0) {
      throw new Error(`build-npm.ts failed: ${result.stderr}`);
    }
  }, 30_000);

  afterAll(async () => {
    await rm(outDir, { recursive: true, force: true });
    await rm(fixtureDir, { recursive: true, force: true });
  });

  it("package.json: published name maruhi / version matches the workspace / bin is maruhi and mh", async () => {
    const manifest = JSON.parse(await readFile(join(outDir, "package.json"), "utf8")) as {
      name: string;
      version: string;
      private?: boolean;
      bin: Record<string, string>;
      os?: string[];
      dependencies?: Record<string, string>;
      engines?: Record<string, string>;
    };
    expect(manifest.name).toBe("maruhi");
    expect(manifest.version).toBe(packageJson.version);
    expect(manifest.private).toBeUndefined();
    expect(Object.keys(manifest.bin).toSorted()).toEqual(["maruhi", "mh"]);
    expect(manifest.bin["maruhi"]).toBe("bin.js");
    expect(manifest.bin["mh"]).toBe("bin.js");
    expect(manifest.dependencies).toBeUndefined();
    expect(manifest.engines?.["bun"]).toMatch(/^>=\d/);
    expect(manifest.os).toEqual(["darwin", "linux"]);
  });

  it("bin.js starts with the launcher in place of bun build's shebang and pragma lines", async () => {
    const lines = (await readFile(join(outDir, "bin.js"), "utf8")).split("\n", 3);
    expect(lines[0]).toBe("#!/bin/sh");
    expect(lines[1]).toBe(
      '// @bun 2>/dev/null || :; exec bun --no-env-file --env-file=/dev/null --config=/dev/null "$0" "$@"',
    );
    expect(lines[2]).not.toMatch(/^\/\/ @bun/);
  });

  it("run as a command, it runs under Bun as already bundled and --version reports the workspace version", () => {
    const result = spawnSync(join(outDir, "bin.js"), ["--version"], {
      cwd: workDir,
      env: runEnv,
      encoding: "utf8",
      timeout: 10_000,
    });
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe(packageJson.version);
    expect(readdirSync(transpilerCacheDir)).toEqual([]);
  });

  it("run as a command, it reads neither the working directory's .env nor its bunfig.toml", () => {
    const run = (command: string, args: readonly string[]) =>
      spawnSync(command, [...args, "config", "get", "server"], {
        cwd: workDir,
        env: runEnv,
        encoding: "utf8",
        timeout: 10_000,
      });
    const binJs = join(outDir, "bin.js");
    expect(run("bun", [binJs]).status).toBe(PRELOAD_EXIT);
    const dotenvOnly = run("bun", ["--config=/dev/null", binJs]);
    expect(dotenvOnly.status).toBe(0);
    expect(dotenvOnly.stdout.trim()).toBe(SERVER_FROM_DOTENV);
    const launched = run(binJs, []);
    expect(launched.status).toBe(0);
    expect(launched.stdout.trim()).toBe("");
  });

  it("the bundle does not embed the whole workspace manifest", async () => {
    const bundle = await readFile(join(outDir, "bin.js"), "utf8");
    expect(bundle).toContain(packageJson.version);
    expect(bundle).not.toContain("build:binaries");
  });

  it("launched under Node.js it exits 1 with a Bun-required notice (never a deep ReferenceError)", () => {
    const result = spawnSync("node", [join(outDir, "bin.js"), "--version"], {
      encoding: "utf8",
      timeout: 10_000,
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Bun");
    expect(result.stderr).not.toContain("ReferenceError");
  });
});
