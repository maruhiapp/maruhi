// The `*.package/command.ts` entry discipline (CLAUDE.md "CLI source
// layout"): a command group living in a package is imported by
// commands/index.ts directly — and by nothing else, not even the
// package's own index.ts (a re-export there widens the surface back to a
// second entry and, on sync, closes the index → command → context →
// rotate-connector → index cycle the layout exists to avoid).
//
// apps/cli/test/** is excluded from ImportLint by design (tests may
// inspect package internals), so this pin is a mechanical walk: every
// relative `from "..."` specifier under src/ is resolved, and the files
// whose specifier lands on a `*.package/command.ts` are collected.

import { readdir, readFile } from "node:fs/promises";
import { join, normalize } from "node:path";

import { describe, expect, it } from "vitest";

const SRC_DIR = join(import.meta.dirname, "..", "src");

/**
 * The .ts files under src/, as src-relative paths in a stable order.
 * Recursive so a file added under a new src/ subdirectory is still picked
 * up — a flat listing would silently skip it (same walk as
 * message-style.test.ts).
 */
async function srcFiles(): Promise<readonly string[]> {
  return (await readdir(SRC_DIR, { recursive: true }))
    .filter((entry) => entry.endsWith(".ts"))
    .map((name) => name.replaceAll("\\", "/"))
    .toSorted();
}

/** A relative specifier (`import ... from` and `export ... from` alike). */
const SPECIFIER = /from\s+"(\.[^"]*)"/g;

interface CommandEntryImport {
  /** src-relative path of the importing file. */
  readonly file: string;
  /** The specifier as written. */
  readonly specifier: string;
  /** src-relative path the specifier resolves to. */
  readonly target: string;
}

/**
 * Every import or re-export whose specifier resolves onto a
 * `*.package/command.ts`, wherever under src/ it is written — a bare
 * `./command.ts` inside the package counts the same as a
 * `../<name>.package/command.ts` from outside.
 */
async function commandEntryImports(): Promise<readonly CommandEntryImport[]> {
  const hits: CommandEntryImport[] = [];
  for (const name of await srcFiles()) {
    const source = await readFile(join(SRC_DIR, name), "utf8");
    for (const match of source.matchAll(SPECIFIER)) {
      const specifier = match[1] ?? "";
      const target = normalize(join(name, "..", specifier)).replaceAll("\\", "/");
      if (/^[^/]+\.package\/command\.ts$/.test(target)) {
        hits.push({ file: name, specifier, target });
      }
    }
  }
  return hits;
}

describe("*.package/command.ts entries (apps/cli/src)", () => {
  it("finds the package command entries (the check isn't idling)", async () => {
    // 3 at introduction (sync / schema / proxy — one import specifier
    // each, all in commands/index.ts): a walk or pattern that stops
    // matching fails here before the exclusive-set check below can pass
    // on an empty collection
    expect((await commandEntryImports()).length).toBeGreaterThanOrEqual(3);
  });

  it("only commands/index.ts imports a package command.ts", async () => {
    const importers = [...new Set((await commandEntryImports()).map((hit) => hit.file))].toSorted();
    expect(importers).toEqual(["commands/index.ts"]);
  });
});
