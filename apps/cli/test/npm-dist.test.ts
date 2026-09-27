// Pins the properties of the npm distribution (the staging that
// scripts/build-npm.ts assembles). Bundling takes a few seconds, so build
// it once and check several properties.

import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import packageJson from "../package.json";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));

describe("npm distribution staging (build-npm)", () => {
  let outDir: string;

  beforeAll(() => {
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
  });

  it("package.json: published name maruhi / version matches the workspace / bin is maruhi and mh", async () => {
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
  });

  it("the bundle runs under Bun and --version reports the workspace version", () => {
    const result = spawnSync("bun", [join(outDir, "bin.js"), "--version"], {
      encoding: "utf8",
      timeout: 10_000,
    });
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe(packageJson.version);
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
