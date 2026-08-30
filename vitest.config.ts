import { defineConfig } from "vitest/config";

// crypto / core / cli は通常環境、server は vitest-pool-workers(workerd 実環境)。
// web / docs はフレームワーク導入(スパイク A / Blume)時にプロジェクトを追加する。
export default defineConfig({
  test: {
    projects: [
      "packages/*/vitest.config.ts",
      "apps/cli/vitest.config.ts",
      "apps/server/vitest.config.ts",
      // web の e2e はビルド済み dist 前提で独立ステップ(CI 9)のまま。unit のみ統合
      "apps/web/vitest.unit.config.ts",
    ],
  },
});
