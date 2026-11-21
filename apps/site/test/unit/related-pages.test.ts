import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vite-plus/test";

const docsDir = join(import.meta.dirname, "..", "..", "src", "content", "docs");
const slugs = readdirSync(docsDir)
  .filter((name) => name.endsWith(".mdx"))
  .map((name) => name.slice(0, -".mdx".length));

function relatedOf(slug: string): string[] {
  const source = readFileSync(join(docsDir, `${slug}.mdx`), "utf8");
  const frontmatter = `${source.split("\n---\n", 1)[0]}\n`;
  const block = /^related:\n((?: {2}- .*\n)+)/m.exec(frontmatter);
  return block === null
    ? []
    : [...String(block[1]).matchAll(/^ {2}- (.+)$/gm)].map((m) => String(m[1]));
}

describe("docs related pages (related: frontmatter)", () => {
  for (const slug of slugs.filter((name) => name !== "index")) {
    it(`${slug} lists 2–4 other docs pages`, () => {
      const related = relatedOf(slug);
      expect(
        related.length,
        `${slug}.mdx lists ${related.length} related pages`,
      ).toBeGreaterThanOrEqual(2);
      expect(related.length).toBeLessThanOrEqual(4);
      const targets = related.map((link) => link.replace(/^\/docs\//, ""));
      expect(related).toEqual(targets.map((target) => `/docs/${target}`));
      expect(slugs).toEqual(expect.arrayContaining(targets));
      expect(targets).not.toContain(slug);
    });
  }
});
