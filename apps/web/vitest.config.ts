import { defineConfig } from "vitest/config";

// e2e check of the web dashboard (cf dev + Playwright).
// Note: intentionally not added to the root vitest.config.ts projects
// (it assumes a prebuilt dist; see docs/notes/spike-a.md for root
// integration).
export default defineConfig({
  test: {
    name: "web-e2e",
    include: ["test/e2e.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
