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

const repoRoot = join(import.meta.dirname, "..", "..", "..", "..");

const TSRS_LINT_FLAG = (
  JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")) as { scripts: { lint: string } }
).scripts.lint.match(/--tsrs-lint=\S+/)![0];

const CLASS_NAME = "className is forbidden.";
const INLINE_STYLE = "Inline style is forbidden.";
const STYLEX_PROPS = "stylex.props on raw DOM is only allowed inside apps/web/src/ui.package/.";
const EVERY_BAN = [CLASS_NAME, INLINE_STYLE, STYLEX_PROPS] as const;

const COMPONENT = `import * as stylex from "@stylexjs/stylex";

export const WithClassName = () => <div className="probe" />;
export const WithStyle = () => <div style={{ color: "red" }} />;
export const WithProps = () => <div {...stylex.props()} />;
`;

const MODULE = `import * as stylex from "@stylexjs/stylex";

export const props = stylex.props();
`;

interface Probe {
  readonly path: string;
  readonly source: string;
  readonly bans: readonly string[];
}

const PROBES: readonly Probe[] = [
  { path: "src/dashboard/Probe.tsx", source: COMPONENT, bans: EVERY_BAN },
  { path: "test/Probe.tsx", source: COMPONENT, bans: EVERY_BAN },
  { path: "src/dashboard/probe.mts", source: MODULE, bans: [STYLEX_PROPS] },
  { path: "src/ui.package/Probe.tsx", source: COMPONENT, bans: [] },
  { path: "src/dashboard/ui.package/Probe.tsx", source: COMPONENT, bans: EVERY_BAN },
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
  tree = mkdtempSync(join(tmpdir(), "maruhi-styling-lint-"));
  mkdirSync(join(tree, "apps", "web"), { recursive: true });
  copyFileSync(join(repoRoot, "vite.config.ts"), join(tree, "vite.config.ts"));
  writeFileSync(join(tree, "package.json"), '{ "name": "maruhi-styling-lint", "private": true }\n');
  symlinkSync(join(repoRoot, "node_modules"), join(tree, "node_modules"));
  for (const probe of PROBES) {
    const file = join(tree, "apps", "web", probe.path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, probe.source);
  }
  const result = spawnSync(
    join(tree, "node_modules", ".bin", "effect-tsgo"),
    [
      TSRS_LINT_FLAG,
      "vp",
      "lint",
      "--format",
      "json",
      ...PROBES.map((probe) => join("apps", "web", probe.path)),
    ],
    { cwd: tree, encoding: "utf8", timeout: 60_000 },
  );
  expect(result.error, result.stderr).toBeUndefined();
  expect([0, 1], result.stderr).toContain(result.status);
  report = JSON.parse(result.stdout) as LintReport;
});

afterAll(() => {
  if (tree !== undefined) rmSync(tree, { recursive: true, force: true });
});

describe("the styling bans of the root vite.config.ts lint block (ADR-0013)", () => {
  it("lints every probe", () => {
    expect(report?.number_of_files).toBe(PROBES.length);
  });

  it.each(PROBES)("$path trips exactly the expected bans", (probe) => {
    const tripped = (report?.diagnostics ?? [])
      .filter(
        (diagnostic) =>
          diagnostic.filename === join("apps", "web", probe.path) &&
          diagnostic.code === "eslint-js(no-restricted-syntax)",
      )
      .map(
        (diagnostic) =>
          EVERY_BAN.find((ban) => diagnostic.message.startsWith(ban)) ?? diagnostic.message,
      );
    expect(tripped.toSorted()).toEqual([...probe.bans].toSorted());
  });
});
