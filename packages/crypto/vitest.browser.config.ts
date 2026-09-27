// Runs the tests in a browser (headless Chromium) (CRYPTO_SPEC §11).
// Not picked up by the root vitest.config.ts glob; run from a dedicated CI step
// (after Playwright Chromium is provisioned) / `bun run test:browser`.
import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";

// Allows swapping the Chromium executable via the same env var as the apps/web e2e
// (for environments that only have a pre-installed browser; default resolution when unset)
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
