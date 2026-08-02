// ブラウザ(Chromium headless)でのテスト実行(CRYPTO_SPEC §11)。
// ルート vitest.config.ts の glob には載せず、CI の独立ステップ(Playwright
// Chromium 導入後)/ `bun run test:browser` から実行する(spike-c の構成)。
import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "crypto-browser",
    include: ["test/**/*.test.ts"],
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(),
      instances: [{ browser: "chromium" }],
    },
  },
});
