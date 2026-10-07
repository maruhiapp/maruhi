// docs/REVIEWING.md is a map for outside reviewers, so its tables must not
// drift. doc-paths.test.ts only checks that a bare filename exists somewhere,
// which is weak here: `invite-link.ts`, `recovery.ts` and `dek-wrap.ts` exist
// in both packages/crypto and the CLI. This test pins the tables:
//   (a) every file cell resolves in its column's directory — a cell starting
//       with `apps/`, `packages/` or `.` is from the repository root;
//   (b) every § reference in a table resolves to a heading of the spec it
//       names (a cell without a spec name means CRYPTO_SPEC); a `-k` list
//       item ref in CRYPTO / AUDIT must also name an existing item k.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const repoRoot = join(import.meta.dirname, "..", "..", "..", "..");
const doc = readFileSync(join(repoRoot, "docs", "REVIEWING.md"), "utf8");
const CRYPTO_DIR = "packages/crypto/src/internal.package";
const SPECS: Record<string, string> = {
  CRYPTO: "CRYPTO_SPEC",
  AUTH: "AUTH_SPEC",
  AUDIT: "AUDIT_SPEC",
};

/** The data rows (cells) of the markdown tables under the `## <n>.` heading. */
function tableRows(section: string): string[][] {
  const body = doc.split(new RegExp(`^## ${section}\\. .*$`, "m"))[1]?.split(/^## /m)[0] ?? "";
  return body
    .split("\n")
    .filter((line) => line.startsWith("| ") && !line.startsWith("|---"))
    .slice(1)
    .map((line) => line.slice(1, -1).split(" | "));
}

/** Backticked file or directory tokens of a cell. */
const filesIn = (cell: string): string[] =>
  [...cell.matchAll(/`([^`\s]+)`/g)].map((m) => m[1]!).filter((t) => /(\.\w+|\/)$/.test(t));

const resolveIn = (dir: string, token: string): string =>
  /^(apps|packages)\/|^\./.test(token) ? token : join(dir, token);

/** Heading ids per spec: `6.3`, `12-5`, `14` … */
const headingIds = (spec: string): Set<string> =>
  new Set(
    [
      ...readFileSync(join(repoRoot, "docs", `${spec}.md`), "utf8").matchAll(
        /^#{2,4} ([\d.-]+?)\.? /gm,
      ),
    ].map((m) => m[1]!),
  );
const HEADINGS = Object.fromEntries(Object.values(SPECS).map((s) => [s, headingIds(s)]));

/** `CRYPTO_SPEC §6.1–§6.4, §1 …; AUTH §12-5` → [[CRYPTO_SPEC, 6.1], …, [AUTH_SPEC, 12-5]]. */
function sectionRefs(cell: string): [string, string][] {
  let spec = "CRYPTO_SPEC";
  return [...cell.matchAll(/\b(CRYPTO|AUTH|AUDIT)(?:_SPEC)?\b|§([\d.]+(?:-\d+)?)/g)].flatMap(
    (m) => {
      if (m[1] !== undefined) spec = SPECS[m[1]]!;
      return m[2] === undefined ? [] : [[spec, m[2].replace(/\.$/, "")] as [string, string]];
    },
  );
}

/** The body of section `id` of a spec: from its heading to the next heading. */
function sectionBody(spec: string, id: string): string {
  const text = readFileSync(join(repoRoot, "docs", `${spec}.md`), "utf8");
  const escaped = id.replace(/\./g, "\\.");
  const after = text.split(new RegExp(`^#{2,4} ${escaped}\\.? .*$`, "m"))[1] ?? "";
  return after.split(/^#{2,4} /m)[0] ?? "";
}

function resolvesTo(spec: string, id: string): boolean {
  if (HEADINGS[spec]!.has(id)) return true;
  // A trailing `-k` is list item k inside the section in CRYPTO / AUDIT
  // (§14.2-12): the section must exist and hold a `k. ` item
  const item = /^(.+)-(\d+)$/.exec(id);
  if (spec === "AUTH_SPEC" || item === null || !HEADINGS[spec]!.has(item[1]!)) return false;
  return new RegExp(`^${item[2]}\\. `, "m").test(sectionBody(spec, item[1]!));
}

describe("docs/REVIEWING.md tables", () => {
  it("(a) resolves every file cell in its column's directory", () => {
    const columns = [CRYPTO_DIR, "apps/server/src", "apps/cli/src", "packages/crypto/test-vectors"];
    const cells = [
      ...tableRows("2").map((row) => [CRYPTO_DIR, row[2]!] as const),
      ...tableRows("3").flatMap((row) => columns.map((dir, i) => [dir, row[i + 2]!] as const)),
    ];
    const missing = cells.flatMap(([dir, cell]) =>
      filesIn(cell)
        .map((token) => resolveIn(dir, token))
        .filter((path) => !existsSync(join(repoRoot, path))),
    );
    expect(cells.length).toBeGreaterThan(60);
    expect(missing).toEqual([]);
  });

  it("(b) resolves every § reference in the tables to a spec heading", () => {
    const refs = ["1", "2", "3"].flatMap((s) => tableRows(s).flat().flatMap(sectionRefs));
    expect(refs.length).toBeGreaterThan(50);
    expect(refs.filter(([spec, id]) => !resolvesTo(spec, id)).map((r) => r.join(" §"))).toEqual([]);
  });
});
