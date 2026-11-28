import { execSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vite-plus/test";

const repoRoot = join(import.meta.dirname, "..", "..", "..", "..");
const adrDir = join(repoRoot, "docs", "adr");

const tracked = new Set(
  execSync("git ls-files", { cwd: repoRoot, encoding: "utf8" }).trim().split("\n"),
);

const RECORD_ADR = /^00(2[1-9]|30)-.*\.md$/;
const HEADING = /^### `([^`]+)`$/gm;
const MOVED = /^- Moved \d{4}-\d{2}-\d{2} from `([^`]+)`/gm;

const records = readdirSync(adrDir)
  .filter((name) => RECORD_ADR.test(name))
  .toSorted()
  .map((name) => {
    const text = readFileSync(join(adrDir, name), "utf8");
    return {
      name,
      headingLines: text.match(/^### .*$/gm) ?? [],
      headings: [...text.matchAll(HEADING)].map((match) => match[1] ?? ""),
      movedFrom: [...text.matchAll(MOVED)].map((match) => match[1] ?? ""),
    };
  });

describe("file-path headings of the record ADRs (docs/adr/0021 to 0030)", () => {
  it("reads the ten record ADRs and their headings (the check isn't idling)", () => {
    expect(records.length).toBe(10);
    expect(records.flatMap((record) => record.headings).length).toBeGreaterThan(1000);
    expect(records.flatMap((record) => record.movedFrom).length).toBeGreaterThan(0);
  });

  it("writes every heading as one path in backticks", () => {
    for (const record of records) {
      expect(record.headingLines, record.name).toEqual(
        record.headings.map((path) => `### \`${path}\``),
      );
    }
  });

  it("names a tracked file in every heading", () => {
    const lost = records.flatMap((record) =>
      record.headings.filter((path) => !tracked.has(path)).map((path) => `${record.name}: ${path}`),
    );
    expect(lost).toEqual([]);
  });

  it("keeps the headings of each ADR in code-point order, each path once", () => {
    for (const record of records) {
      expect(record.headings, record.name).toEqual([...new Set(record.headings)].toSorted());
    }
  });

  it("names a path that is gone in every `Moved` line", () => {
    const stale = records.flatMap((record) =>
      record.movedFrom.filter((path) => tracked.has(path)).map((path) => `${record.name}: ${path}`),
    );
    expect(stale).toEqual([]);
  });
});
