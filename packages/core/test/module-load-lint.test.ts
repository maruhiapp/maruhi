import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";

const repoRoot = join(import.meta.dirname, "..", "..", "..");

const TSRS_LINT_FLAG = (
  JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")) as { scripts: { lint: string } }
).scripts.lint.match(/--tsrs-lint=\S+/)![0];

const DYNAMIC_IMPORT = "A dynamic import() names a relative path literal.";
const REQUIRE = "Shipped source loads modules with import only.";
const MASTER_KEY = 'User-facing text must not say "master key".';
const INLINE_SUCCESS_STRUCT = "Do not write an inline Schema.Struct into success.";
const EVERY_BAN = [DYNAMIC_IMPORT, REQUIRE, MASTER_KEY, INLINE_SUCCESS_STRUCT] as const;

const PACKAGE_SPECIFIER = `export const load = async () => (await import("effect/http")).FetchHttpClient;
`;

const EVERY_SPECIFIER_SHAPE = `export const named = async () => (await import("@maruhi/core")).decodeUserId;
export const computed = async (specifier: string) => import(specifier);
export const template = async () => import(\`./sibling.ts\`);
export const relative = async () => import("./sibling.ts");
export const parent = async () => import("../sibling.ts");
export type Shape = typeof import("@maruhi/core");
export const wording = "master key";
`;

const REQUIRE_SHAPES = `import { createRequire } from "node:module";

export const plain = require("effect/http").FetchHttpClient;
export const created = createRequire(import.meta.url)("effect/http").FetchHttpClient;
export const meta = import.meta.require("effect/http").FetchHttpClient;
`;

const NODE_MODULE_SHAPES = `import nodeModule from "node:module";
import * as bareModule from "module";

export const fromDefault = nodeModule.createRequire(import.meta.url)("effect/http");
export const fromNamespace = bareModule.createRequire(import.meta.url)("effect/http");
`;

const NODE_MODULE_REEXPORTS = `export { createRequire } from "node:module";
export * from "module";
export * as nodeModule from "node:module";
`;

const ASTRO = `---
const frontmatter = await import("effect/http");
---

<script>
  const client = await import("effect/http");
</script>
`;

const API_SCHEMA = `import { Schema } from "effect";
import { HttpApiEndpoint } from "effect/unstable/httpapi";

export const load = async () => import("@maruhi/core");
export const endpoint = HttpApiEndpoint.get("probe", "/probe", {
  success: Schema.Struct({ ok: Schema.Boolean }),
});
`;

interface Probe {
  readonly path: string;
  readonly source: string;
  readonly bans: readonly string[];
}

const PROBES: readonly Probe[] = [
  {
    path: "apps/cli/src/probe.ts",
    source: EVERY_SPECIFIER_SHAPE,
    bans: [DYNAMIC_IMPORT, DYNAMIC_IMPORT, DYNAMIC_IMPORT, MASTER_KEY],
  },
  {
    path: "apps/cli/src/probe.package/probe.ts",
    source: PACKAGE_SPECIFIER,
    bans: [DYNAMIC_IMPORT],
  },
  { path: "apps/cli/src/probe.mts", source: PACKAGE_SPECIFIER, bans: [DYNAMIC_IMPORT] },
  { path: "apps/cli/src/require.ts", source: REQUIRE_SHAPES, bans: [REQUIRE, REQUIRE, REQUIRE] },
  { path: "apps/server/src/require.ts", source: REQUIRE_SHAPES, bans: [REQUIRE, REQUIRE, REQUIRE] },
  {
    path: "packages/core/src/require.ts",
    source: REQUIRE_SHAPES,
    bans: [REQUIRE, REQUIRE, REQUIRE],
  },
  { path: "apps/cli/src/node-module.ts", source: NODE_MODULE_SHAPES, bans: [REQUIRE, REQUIRE] },
  { path: "apps/server/src/node-module.ts", source: NODE_MODULE_SHAPES, bans: [REQUIRE, REQUIRE] },
  {
    path: "apps/cli/src/node-module-reexport.ts",
    source: NODE_MODULE_REEXPORTS,
    bans: [REQUIRE, REQUIRE, REQUIRE],
  },
  {
    path: "packages/core/src/node-module-reexport.ts",
    source: NODE_MODULE_REEXPORTS,
    bans: [REQUIRE, REQUIRE, REQUIRE],
  },
  { path: "apps/cli/test/node-module-reexport.ts", source: NODE_MODULE_REEXPORTS, bans: [] },
  { path: "apps/server/src/probe.ts", source: PACKAGE_SPECIFIER, bans: [DYNAMIC_IMPORT] },
  { path: "apps/server/src/do/probe.ts", source: PACKAGE_SPECIFIER, bans: [DYNAMIC_IMPORT] },
  { path: "packages/core/src/probe.ts", source: PACKAGE_SPECIFIER, bans: [DYNAMIC_IMPORT] },
  { path: "packages/crypto/src/probe.ts", source: PACKAGE_SPECIFIER, bans: [DYNAMIC_IMPORT] },
  {
    path: "packages/api-schema/src/probe.ts",
    source: API_SCHEMA,
    bans: [DYNAMIC_IMPORT, INLINE_SUCCESS_STRUCT],
  },
  { path: "apps/site/src/probe.ts", source: PACKAGE_SPECIFIER, bans: [DYNAMIC_IMPORT] },
  {
    path: "apps/site/src/pages/probe.astro",
    source: ASTRO,
    bans: [DYNAMIC_IMPORT, DYNAMIC_IMPORT],
  },
  {
    path: "apps/site/src/components/ui/search/providers/pagefind.ts",
    source: PACKAGE_SPECIFIER,
    bans: [],
  },
  { path: "apps/cli/test/probe.ts", source: PACKAGE_SPECIFIER, bans: [] },
  { path: "apps/cli/test/require.ts", source: REQUIRE_SHAPES, bans: [] },
  { path: "apps/server/test/probe.ts", source: PACKAGE_SPECIFIER, bans: [] },
];

interface Diagnostic {
  readonly code: string;
  readonly filename: string;
  readonly message: string;
}

interface LintReport {
  readonly diagnostics: readonly Diagnostic[];
  readonly number_of_files: number;
}

let tree: string | undefined;
let report: LintReport | undefined;

beforeAll(() => {
  tree = mkdtempSync(join(tmpdir(), "maruhi-module-load-lint-"));
  copyFileSync(join(repoRoot, "vite.config.ts"), join(tree, "vite.config.ts"));
  writeFileSync(
    join(tree, "package.json"),
    '{ "name": "maruhi-module-load-lint", "private": true }\n',
  );
  symlinkSync(join(repoRoot, "node_modules"), join(tree, "node_modules"));
  for (const probe of PROBES) {
    const file = join(tree, probe.path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, probe.source);
  }
  const result = spawnSync(
    join(tree, "node_modules", ".bin", "effect-tsgo"),
    [TSRS_LINT_FLAG, "vp", "lint", "--format", "json", ...PROBES.map((probe) => probe.path)],
    { cwd: tree, encoding: "utf8", timeout: 60_000 },
  );
  expect(result.error, result.stderr).toBeUndefined();
  expect([0, 1], result.stderr).toContain(result.status);
  report = JSON.parse(result.stdout) as LintReport;
});

afterAll(() => {
  if (tree !== undefined) rmSync(tree, { recursive: true, force: true });
});

describe("the module-load bans of the root vite.config.ts lint block", () => {
  it("lints every probe", () => {
    expect(report?.number_of_files).toBe(PROBES.length);
  });

  it.each(PROBES)("$path trips exactly the expected bans", (probe) => {
    const tripped = (report?.diagnostics ?? [])
      .filter(
        (diagnostic) =>
          diagnostic.filename === probe.path &&
          diagnostic.code === "eslint-js(no-restricted-syntax)",
      )
      .map(
        (diagnostic) =>
          EVERY_BAN.find((ban) => diagnostic.message.startsWith(ban)) ?? diagnostic.message,
      );
    expect(tripped.toSorted()).toEqual([...probe.bans].toSorted());
  });
});
