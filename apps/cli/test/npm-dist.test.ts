// Pins the properties of the npm distribution (the staging that
// scripts/build-npm.ts assembles). Bundling takes a few seconds, so build
// it once and check several properties.

import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import packageJson from "../package.json";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));

// The working directory the bundle runs in for the tests below, a stand-in for
// a cloned repository: its .env points MARUHI_CONFIG_DIR at a config whose
// server is SERVER_FROM_DOTENV, and its bunfig.toml preloads a file that
// exits with PRELOAD_EXIT
const SERVER_FROM_DOTENV = "https://from-dotenv.invalid";
const PRELOAD_EXIT = 97;

describe("npm distribution staging (build-npm)", () => {
  let outDir: string;
  let fixtureDir: string;
  let workDir: string;
  // Where Bun would cache a transpiled bin.js; it stays empty while Bun takes
  // bin.js as already bundled
  let transpilerCacheDir: string;
  // The environment of each run: no MARUHI_CONFIG_DIR, so only the .env can
  // set it, an empty XDG_CONFIG_HOME in place of the developer's config, and
  // the transpiler cache above
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
      // spawnSync blocks the event loop, so vitest's hook timeout (30s
      // below) can't interrupt the synchronous call — kill the child before
      // the hook's ceiling
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
    // Values must be `./`-free relative paths: npm 11's publish-time
    // normalization judges `./bin.js` invalid and silently drops the whole
    // bin entry (measured during the v0.1.0-rc.1 publish failure — had it
    // passed, a command-less package would have shipped)
    expect(manifest.bin["maruhi"]).toBe("bin.js");
    expect(manifest.bin["mh"]).toBe("bin.js");
    // Workspace dependencies and the effect beta are folded into the
    // bundle (ADR-0015). A resurrected dependency would point at
    // unpublished @maruhi/* and break — pin dependencies away
    expect(manifest.dependencies).toBeUndefined();
    expect(manifest.engines?.["bun"]).toMatch(/^>=\d/);
    // The launcher at the top of bin.js is for Linux and macOS
    expect(manifest.os).toEqual(["darwin", "linux"]);
  });

  it("bin.js starts with the launcher in place of bun build's shebang and pragma lines", async () => {
    const lines = (await readFile(join(outDir, "bin.js"), "utf8")).split("\n", 3);
    expect(lines[0]).toBe("#!/bin/sh");
    // --env-file=/dev/null is for Bun before 1.3.3, which ignores
    // --no-env-file. On the Bun these tests run with, either flag alone keeps
    // the .env out, so only this line pins both
    expect(lines[1]).toBe(
      '// @bun 2>/dev/null || :; exec bun --no-env-file --env-file=/dev/null --config=/dev/null "$0" "$@"',
    );
    // bun build's own `// @bun` line was replaced, not left as a third line
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
    // Bun saw the `// @bun` pragma: it did not transpile bin.js into its cache
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
    // The directory works on plain Bun: its preload runs, and without the
    // bunfig.toml its .env sets the server
    const binJs = join(outDir, "bin.js");
    expect(run("bun", [binJs]).status).toBe(PRELOAD_EXIT);
    const dotenvOnly = run("bun", ["--config=/dev/null", binJs]);
    expect(dotenvOnly.status).toBe(0);
    expect(dotenvOnly.stdout.trim()).toBe(SERVER_FROM_DOTENV);
    // Through the launcher neither applies: no server is set
    const launched = run(binJs, []);
    expect(launched.status).toBe(0);
    expect(launched.stdout.trim()).toBe("");
  });

  it("the bundle does not embed the whole workspace manifest", async () => {
    // As long as cli.ts's package.json import stays a named import
    // (version only), it tree-shakes; reverting to a default import would
    // duplicate the whole manifest — scripts, dependency pins — into the
    // npm distribution and every binary (measured: bun 1.3.14).
    // The probe token is a scripts name unique to our own manifest:
    // "devDependencies" could appear in bundled dependencies' own code and
    // false-fail. And since bun embeds object-literal keys unquoted when it
    // can, a quoted check like '"devDependencies"' wouldn't fire anyway
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
