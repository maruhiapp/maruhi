import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vite-plus/test";

const repoRoot = join(import.meta.dirname, "..", "..", "..", "..");
const read = (name: string): string => readFileSync(join(repoRoot, "docs", name), "utf8");

function section(doc: string, start: RegExp, level: number): string {
  const [, rest = ""] = doc.split(start);
  return rest.split(new RegExp(`^#{1,${level}} `, "m"))[0] ?? "";
}

const itemNumbers = (body: string): number[] =>
  [...body.matchAll(/^(\d+)\. \*\*/gm)].map((match) => Number(match[1]));

const specItems = itemNumbers(
  section(read("CRYPTO_SPEC.md"), /^### 14\.3 Explicit non-guarantees.*$/m, 3),
);
const readerItems = itemNumbers(
  section(read("THREAT_MODEL.md"), /^## Declared non-guarantees \(CRYPTO_SPEC §14\.3\)$/m, 2),
);

describe("docs/THREAT_MODEL.md lists every CRYPTO_SPEC §14.3 item", () => {
  it("finds the §14.3 items (the check isn't idling)", () => {
    expect(specItems.length).toBeGreaterThanOrEqual(10);
    expect(specItems).toEqual(specItems.map((_, index) => index + 1));
  });

  it("numbers the reader list exactly like §14.3", () => {
    expect(readerItems).toEqual(specItems);
  });
});
