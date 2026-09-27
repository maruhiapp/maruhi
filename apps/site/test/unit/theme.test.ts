// Ruling B (docs/notes/web-design-pass.md §4 "rulings recorded while
// implementing DP2"): the site's generated theme artifacts are a mapping
// of apps/web/theme/maruhi.css, and the committed content must match a
// fresh regeneration (after changing the dashboard theme, run
// `bun run --filter @maruhi/site theme:build`).
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { extractBrand, paths, renderAll } from "../../scripts/theme.ts";

const repoRoot = join(import.meta.dirname, "..", "..", "..", "..");

describe("site theme artifacts", () => {
  it("match a fresh render from apps/web/theme/maruhi.css (no drift)", () => {
    for (const [relative, expected] of renderAll(repoRoot)) {
      const actual = readFileSync(join(repoRoot, relative));
      const same =
        typeof expected === "string"
          ? actual.toString("utf8") === expected
          : actual.equals(expected);
      expect(same, `${relative} is stale — run: bun run --filter @maruhi/site theme:build`).toBe(
        true,
      );
    }
  });

  it("carry the vermilion accent of the ㊙ mark (DP1 rulings A / B)", () => {
    const brand = extractBrand(readFileSync(join(repoRoot, paths.webThemeCss), "utf8"));
    // The logo SVG's fill = the light-side accent (DP1 ruling A)
    const logo = readFileSync(join(repoRoot, paths.webLogo), "utf8");
    expect(logo.toLowerCase()).toContain(`fill="${brand.accent.light.toLowerCase()}"`);
    // The generated theme.css carries the accent of both modes
    const css = readFileSync(join(repoRoot, paths.themeCss), "utf8");
    expect(css).toContain(`--blume-accent: ${brand.accent.light.toLowerCase()};`);
    expect(css).toContain(`--blume-accent: ${brand.accent.dark.toLowerCase()};`);
    // Raw hex lives only in the generated artifacts (blume.config.ts
    // references tokens.ts)
    const config = readFileSync(join(repoRoot, "apps/site/blume.config.ts"), "utf8");
    expect(config.replace(/\/\/.*$/gm, "")).not.toMatch(/#[0-9a-fA-F]{6}\b/);
  });
});
