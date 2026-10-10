// docs/THREAT_MODEL.md condenses CRYPTO_SPEC §14, and CRYPTO_SPEC §14 says it
// lists every §14.3 item. This test pins that claim: the numbered items under
// THREAT_MODEL's "Declared non-guarantees" match §14.3's numbering one to one,
// so a non-guarantee added to (or removed from) the spec fails here until the
// reader document follows.

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const repoRoot = join(import.meta.dirname, "..", "..", "..", "..");
const read = (name: string): string => readFileSync(join(repoRoot, "docs", name), "utf8");

/** The body between a heading matched by `start` and the next heading of the same or a higher level. */
function section(doc: string, start: RegExp, level: number): string {
  const [, rest = ""] = doc.split(start);
  return rest.split(new RegExp(`^#{1,${level}} `, "m"))[0] ?? "";
}

/** The numbers of a section's top-level `N. **title**` list items. */
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
    // 10 at introduction: a heading rename or a list-format change fails
    // here before the comparison below can pass on two empty lists
    expect(specItems.length).toBeGreaterThanOrEqual(10);
    expect(specItems).toEqual(specItems.map((_, index) => index + 1));
  });

  it("numbers the reader list exactly like §14.3", () => {
    expect(readerItems).toEqual(specItems);
  });
});
