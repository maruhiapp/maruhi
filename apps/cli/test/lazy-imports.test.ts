// The lazy-import shape (P-6 — commands/shared.ts's note). fallow credits
// an export consumed through `import()` only when the names are picked
// inside the `.then`: a bare `Effect.promise(() => import("./m.ts"))` hides
// the edge, and `.then((m) => m)` credits every export of the module. So
// every `import()` under src/ is written
//
//   const { a, b } = yield* Effect.promise(() =>
//     import("./m.ts").then(({ a, b }) => ({ a, b })),
//   );
//
// (or `Effect.flatMap(<that load>, ({ a }) => ...)`), and the names the
// consumer binds are exactly the names the load picks — a stale extra name
// in the `.then` would keep a dead export looking used.

import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const SRC_DIR = join(import.meta.dirname, "..", "src");

async function srcFiles(): Promise<readonly string[]> {
  return (await readdir(SRC_DIR, { recursive: true }))
    .filter((entry) => entry.endsWith(".ts"))
    .map((name) => name.replaceAll("\\", "/"))
    .toSorted();
}

/** Formatting-independent source: trailing commas dropped, whitespace collapsed, no padding inside parentheses. */
function normalized(source: string): string {
  return source
    .replaceAll(/,(\s*[}\])])/g, "$1")
    .replaceAll(/\s+/g, " ")
    .replaceAll("( ", "(")
    .replaceAll(" )", ")");
}

const IMPORT_CALL = /\bimport\("/g;
const NAMES = String.raw`\{ ([\w, ]+) \}`;
const LOAD = String.raw`import\("([^"]+)"\)\.then\(\(${NAMES}\) => \(${NAMES}\)\)`;
const BOUND_LOAD = new RegExp(String.raw`const ${NAMES} = yield\* Effect\.promise\(\(\) => ${LOAD}\)`, "g");
const MAPPED_LOAD = new RegExp(String.raw`Effect\.promise\(\(\) => ${LOAD}\), \(${NAMES}\) =>`, "g");

interface LazyImport {
  readonly file: string;
  readonly specifier: string;
  readonly bound: string;
  readonly picked: string;
  readonly returned: string;
}

async function lazyImports(): Promise<{
  readonly calls: number;
  readonly loads: readonly LazyImport[];
}> {
  let calls = 0;
  const loads: LazyImport[] = [];
  for (const file of await srcFiles()) {
    const source = normalized(await readFile(join(SRC_DIR, file), "utf8"));
    calls += [...source.matchAll(IMPORT_CALL)].length;
    for (const match of source.matchAll(BOUND_LOAD)) {
      const [, bound = "", specifier = "", picked = "", returned = ""] = match;
      loads.push({ file, specifier, bound, picked, returned });
    }
    for (const match of source.matchAll(MAPPED_LOAD)) {
      const [, specifier = "", picked = "", returned = "", bound = ""] = match;
      loads.push({ file, specifier, bound, picked, returned });
    }
  }
  return { calls, loads };
}

describe("lazy imports (apps/cli/src, P-6)", () => {
  it("finds the lazy imports (the check isn't idling)", async () => {
    // 192 at introduction: a walk or pattern that stops matching fails here
    // before the shape checks below can pass on an empty collection
    expect((await lazyImports()).calls).toBeGreaterThanOrEqual(150);
  });

  it("writes every import() in the picked-names shape", async () => {
    const { calls, loads } = await lazyImports();
    expect(loads.length).toBe(calls);
  });

  it("binds exactly the names each load picks", async () => {
    const mismatched = (await lazyImports()).loads.filter(
      (load) => load.bound !== load.picked || load.picked !== load.returned,
    );
    expect(mismatched).toEqual([]);
  });
});
