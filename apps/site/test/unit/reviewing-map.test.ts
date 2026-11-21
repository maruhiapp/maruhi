import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vite-plus/test";

const repoRoot = join(import.meta.dirname, "..", "..", "..", "..");
const doc = readFileSync(join(repoRoot, "docs", "REVIEWING.md"), "utf8");
const CRYPTO_DIR = "packages/crypto/src/internal.package";
const SPECS: Record<string, string> = {
  CRYPTO: "CRYPTO_SPEC",
  AUTH: "AUTH_SPEC",
  AUDIT: "AUDIT_SPEC",
};

function tableRows(section: string): string[][] {
  const body = doc.split(new RegExp(`^## ${section}\\. .*$`, "m"))[1]?.split(/^## /m)[0] ?? "";
  return body
    .split("\n")
    .filter((line) => line.startsWith("| ") && !line.startsWith("|---"))
    .slice(1)
    .map((line) => line.slice(1, -1).split(" | "));
}

const filesIn = (cell: string): string[] =>
  [...cell.matchAll(/`([^`\s]+)`/g)].map((m) => m[1]!).filter((t) => /(\.\w+|\/)$/.test(t));

const resolveIn = (dir: string, token: string): string =>
  /^(apps|packages)\/|^\./.test(token) ? token : join(dir, token);

const headingIds = (spec: string): Set<string> =>
  new Set(
    [
      ...readFileSync(join(repoRoot, "docs", `${spec}.md`), "utf8").matchAll(
        /^#{2,4} ([\d.-]+?)\.? /gm,
      ),
    ].map((m) => m[1]!),
  );
const HEADINGS = Object.fromEntries(Object.values(SPECS).map((s) => [s, headingIds(s)]));

function sectionRefs(cell: string): [string, string][] {
  let spec = "CRYPTO_SPEC";
  return [...cell.matchAll(/\b(CRYPTO|AUTH|AUDIT)(?:_SPEC)?\b|§([\d.]+(?:-\d+)?)/g)].flatMap(
    (m) => {
      if (m[1] !== undefined) spec = SPECS[m[1]]!;
      return m[2] === undefined ? [] : [[spec, m[2].replace(/\.$/, "")] as [string, string]];
    },
  );
}

function sectionBody(spec: string, id: string): string {
  const text = readFileSync(join(repoRoot, "docs", `${spec}.md`), "utf8");
  const escaped = id.replace(/\./g, "\\.");
  const after = text.split(new RegExp(`^#{2,4} ${escaped}\\.? .*$`, "m"))[1] ?? "";
  return after.split(/^#{2,4} /m)[0] ?? "";
}

function resolvesToListItem(spec: string, id: string): boolean {
  const [, section = "", item = ""] = /^(.+)-(\d+)$/.exec(id) ?? [];
  return (
    HEADINGS[spec]!.has(section) && new RegExp(`^${item}\\. `, "m").test(sectionBody(spec, section))
  );
}

const resolvesTo = (spec: string, id: string): boolean =>
  HEADINGS[spec]!.has(id) || (spec !== "AUTH_SPEC" && resolvesToListItem(spec, id));

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
