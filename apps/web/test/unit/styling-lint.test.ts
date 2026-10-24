// The styling bans of apps/web/.oxlintrc.json (ADR-0013 — the
// styling-discipline section of CLAUDE.md: no className, no inline style,
// and stylex.props on raw DOM only inside src/ui.package) reach the web's
// files. oxlint reports nothing for an override whose globs match no
// file, so a ban that stops applying fails silently: from 2026-08-01,
// when apps/web/.oxlintrc.json was added, the root config's copy of these
// bans matched no web file, because oxlint matches an inherited
// override's globs against the path relative to apps/web (see the comment
// there). This test copies both configs, unchanged, into a temporary
// tree, writes probe files that break the bans, and runs oxlint on them
// with nested configs, as `bun run lint` does.

import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

const repoRoot = join(import.meta.dirname, "..", "..", "..", "..");

/** The start of each ban's message (apps/web/.oxlintrc.json). */
const CLASS_NAME = "className is forbidden.";
const INLINE_STYLE = "Inline style is forbidden.";
const STYLEX_PROPS = "stylex.props on raw DOM is only allowed inside apps/web/src/ui.package/.";
const EVERY_BAN = [CLASS_NAME, INLINE_STYLE, STYLEX_PROPS] as const;

/** A component that breaks each ban once. */
const COMPONENT = `import * as stylex from "@stylexjs/stylex";

export const WithClassName = () => <div className="probe" />;
export const WithStyle = () => <div style={{ color: "red" }} />;
export const WithProps = () => <div {...stylex.props()} />;
`;

/** A module with no JSX that calls stylex.props. */
const MODULE = `import * as stylex from "@stylexjs/stylex";

export const props = stylex.props();
`;

interface Probe {
  /** The probe's path relative to apps/web. */
  readonly path: string;
  readonly source: string;
  /** The bans it must trip, each once. */
  readonly bans: readonly string[];
}

const PROBES: readonly Probe[] = [
  { path: "src/dashboard/Probe.tsx", source: COMPONENT, bans: EVERY_BAN },
  // The bans cover the whole web tree, not only the bundle source
  { path: "test/Probe.tsx", source: COMPONENT, bans: EVERY_BAN },
  // ... in every module extension
  { path: "src/dashboard/probe.mts", source: MODULE, bans: [STYLEX_PROPS] },
  // src/ui.package is the one exemption
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
  for (const config of [".oxlintrc.json", join("apps", "web", ".oxlintrc.json")]) {
    copyFileSync(join(repoRoot, config), join(tree, config));
  }
  // The configs' plugins resolve from the repository's dependencies, as
  // they do in the repository (rmSync removes the links, never their
  // targets)
  for (const modules of ["node_modules", join("apps", "web", "node_modules")]) {
    symlinkSync(join(repoRoot, modules), join(tree, modules));
  }
  for (const probe of PROBES) {
    const file = join(tree, "apps", "web", probe.path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, probe.source);
  }
  // The probes are named explicitly: oxlint lints them with the nested
  // config of apps/web, as it lints the repository's files
  const result = spawnSync(
    join(tree, "node_modules", ".bin", "oxlint"),
    ["--format", "json", ...PROBES.map((probe) => join("apps", "web", probe.path))],
    { cwd: tree, encoding: "utf8", timeout: 60_000 },
  );
  // Exit 1 = diagnostics reported; anything else is a failed run
  expect(result.error, result.stderr).toBeUndefined();
  expect([0, 1], result.stderr).toContain(result.status);
  report = JSON.parse(result.stdout) as LintReport;
});

afterAll(() => {
  if (tree !== undefined) rmSync(tree, { recursive: true, force: true });
});

describe("the styling bans of apps/web/.oxlintrc.json (ADR-0013)", () => {
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
