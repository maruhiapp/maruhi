import { defineConfig } from "vitest/config";

// 3 プロジェクト: node(通常環境の基準)/ workerd(vitest-pool-workers)/ browser(playwright)。
// Bun ランタイムは vitest では検証できないため src/run-in-bun.ts を直接実行する。
export default defineConfig({
  test: {
    projects: ["vitest.node.config.ts", "vitest.workerd.config.ts", "vitest.browser.config.ts"],
  },
});
