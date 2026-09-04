// 裁定 B(docs/notes/web-design-pass.md §4「DP2 実装時の裁定録」): サイトのテーマ生成物は
// apps/web/theme/maruhi.css の写像であり、コミット済みの内容が再生成結果と一致しなければ
// ならない(ダッシュボードのテーマを変えたら `bun run --filter @maruhi/site theme:build`)。
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

  it("carry the vermilion accent of the ㊙ mark (DP1 裁定 A / B)", () => {
    const brand = extractBrand(readFileSync(join(repoRoot, paths.webThemeCss), "utf8"));
    // ロゴ SVG の fill = light 側の accent(DP1 裁定 A)
    const logo = readFileSync(join(repoRoot, paths.webLogo), "utf8");
    expect(logo.toLowerCase()).toContain(`fill="${brand.accent.light.toLowerCase()}"`);
    // 生成 theme.css は両モードの accent を持つ
    const css = readFileSync(join(repoRoot, paths.themeCss), "utf8");
    expect(css).toContain(`--blume-accent: ${brand.accent.light.toLowerCase()};`);
    expect(css).toContain(`--blume-accent: ${brand.accent.dark.toLowerCase()};`);
    // 生 hex は生成物にしか無い(blume.config.ts は tokens.ts を参照する)
    const config = readFileSync(join(repoRoot, "apps/site/blume.config.ts"), "utf8");
    expect(config.replace(/\/\/.*$/gm, "")).not.toMatch(/#[0-9a-fA-F]{6}\b/);
  });
});
