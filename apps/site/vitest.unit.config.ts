import { defineConfig } from "vitest/config";

// apex サイト(Blume)のユニットテスト: テーマ生成物(theme.css / tokens.ts / logo-dark.svg /
// 複製資産)が apps/web/theme/maruhi.css からの再生成と一致すること(裁定 B の漂流検知)。
// ビルドなしで走るためルート vitest.config.ts の projects に載せる(品質ゲート 7)。
export default defineConfig({
  test: {
    name: "site-unit",
    include: ["test/unit/**/*.test.ts"],
  },
});
