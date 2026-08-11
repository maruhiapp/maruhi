import { defineConfig } from "vitest/config";

// web ダッシュボードの e2e 検証(wrangler dev + Playwright)。
// 注意: ルート vitest.config.ts の projects には意図的に追加していない
// (ビルド済み dist を前提とするため。root 統合は docs/notes/spike-a.md 参照)。
export default defineConfig({
  test: {
    name: "web-e2e",
    include: ["test/e2e.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
