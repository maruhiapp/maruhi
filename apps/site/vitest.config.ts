import { defineConfig } from "vitest/config";

// apex サイトの e2e(wrangler dev + Playwright)。ビルド済み dist(+ _headers)前提なので
// ルート vitest.config.ts の projects には入れず、CI の独立ステップで実行する(web e2e と同型)。
export default defineConfig({
  test: {
    name: "site-e2e",
    include: ["test/e2e.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
