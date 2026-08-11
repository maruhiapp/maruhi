// ブラウザ(Chromium headless)でのテスト実行(CRYPTO_SPEC §11)。
// ルート vitest.config.ts の glob には載せず、CI の独立ステップ(Playwright
// Chromium 導入後)/ `bun run test:browser` から実行する(spike-c の構成)。
import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";

// apps/web の e2e と同じ環境変数で Chromium 実行体を差し替え可能にする
// (プリインストール済みブラウザだけがある実行環境向け。未設定なら既定解決)
const executablePath = process.env["PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"];

export default defineConfig({
  test: {
    name: "crypto-browser",
    include: ["test/**/*.test.ts"],
    browser: {
      enabled: true,
      headless: true,
      provider: playwright({
        launchOptions: executablePath ? { executablePath } : {},
      }),
      instances: [{ browser: "chromium" }],
    },
  },
});
