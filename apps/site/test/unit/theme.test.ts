import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vite-plus/test";

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
    const logo = readFileSync(join(repoRoot, paths.webLogo), "utf8");
    expect(logo.toLowerCase()).toContain(`fill="${brand.accent.light.toLowerCase()}"`);
    const css = readFileSync(join(repoRoot, paths.themeCss), "utf8");
    expect(css).toContain(`--nb-primary: ${brand.accent.light.toLowerCase()};`);
    expect(css).toContain(`--nb-primary: ${brand.accent.dark.toLowerCase()};`);
    const config = readFileSync(join(repoRoot, "apps/site/astro.config.ts"), "utf8");
    expect(config.replace(/\/\/.*$/gm, "")).not.toMatch(/#[0-9a-fA-F]{6}\b/);
  });
});
