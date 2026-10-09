// Pins the "Related pages" cards (Blume `related:` frontmatter) at the foot of
// every docs page. Blume renders cards only for the links a page lists — it
// generates none — so a new page that forgets the field silently ships
// without them. Every page but the index (which opens with its own cards)
// names 2–4 other docs pages, each in the `/docs/<slug>` form the body links
// use. Whether a target page exists is `blume validate`'s job (CI 8d2); this
// check also pins that the slug names a page in this directory, so a
// renamed page fails here first.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const docsDir = join(import.meta.dirname, "..", "..", "docs");
const slugs = readdirSync(docsDir)
  .filter((name) => name.endsWith(".mdx"))
  .map((name) => name.slice(0, -".mdx".length));

/** The `related:` list of a page's frontmatter (empty when the field is absent). */
function relatedOf(slug: string): string[] {
  const source = readFileSync(join(docsDir, `${slug}.mdx`), "utf8");
  const frontmatter = `${source.split("\n---\n", 1)[0]}\n`;
  const block = /^related:\n((?: {2}- .*\n)+)/m.exec(frontmatter);
  return block === null
    ? []
    : [...String(block[1]).matchAll(/^ {2}- (.+)$/gm)].map((m) => String(m[1]));
}

describe("docs related pages (Blume related: frontmatter)", () => {
  for (const slug of slugs.filter((name) => name !== "index")) {
    it(`${slug} lists 2–4 other docs pages`, () => {
      const related = relatedOf(slug);
      expect(
        related.length,
        `${slug}.mdx lists ${related.length} related pages`,
      ).toBeGreaterThanOrEqual(2);
      expect(related.length).toBeLessThanOrEqual(4);
      const targets = related.map((link) => link.replace(/^\/docs\//, ""));
      // Every entry is a /docs/<slug> link to another page in this directory
      expect(related).toEqual(targets.map((target) => `/docs/${target}`));
      expect(slugs).toEqual(expect.arrayContaining(targets));
      expect(targets).not.toContain(slug);
    });
  }
});
