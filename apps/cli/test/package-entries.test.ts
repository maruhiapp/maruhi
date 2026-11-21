import { readdir, readFile } from "node:fs/promises";
import { join, normalize } from "node:path";

import { describe, expect, it } from "vite-plus/test";

const SRC_DIR = join(import.meta.dirname, "..", "src");

async function srcFiles(): Promise<readonly string[]> {
  return (await readdir(SRC_DIR, { recursive: true }))
    .filter((entry) => entry.endsWith(".ts"))
    .map((name) => name.replaceAll("\\", "/"))
    .toSorted();
}

const SPECIFIER = /from\s+"(\.[^"]*)"/g;

interface CommandEntryImport {
  readonly file: string;
  readonly specifier: string;
  readonly target: string;
}

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
    expect((await commandEntryImports()).length).toBeGreaterThanOrEqual(3);
  });

  it("only commands/index.ts imports a package command.ts", async () => {
    const importers = [...new Set((await commandEntryImports()).map((hit) => hit.file))].toSorted();
    expect(importers).toEqual(["commands/index.ts"]);
  });
});
