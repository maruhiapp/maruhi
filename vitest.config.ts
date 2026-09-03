import { defineConfig } from "vitest/config";

// crypto / core / cli は通常環境、server は @cloudflare/vitest-plugin(workerd 実環境)。
// web(ダッシュボード)と site(LP + docs — Blume)の e2e はビルド済み dist 前提の独立ステップ。
export default defineConfig({
  test: {
    projects: [
      "packages/*/vitest.config.ts",
      "apps/cli/vitest.config.ts",
      "apps/server/vitest.config.ts",
      // web の e2e はビルド済み dist 前提で独立ステップ(CI 9)のまま。unit のみ統合
      "apps/web/vitest.unit.config.ts",
      // site の e2e も同様に独立ステップ(CI 9b)。unit(テーマ生成物の漂流検知)のみ統合
      "apps/site/vitest.unit.config.ts",
    ],
  },
});
