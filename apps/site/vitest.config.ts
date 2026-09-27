import { defineConfig } from "vitest/config";

// e2e for the apex site (wrangler dev + Playwright). Since it presumes a
// built dist (+ _headers), it is not in the root vitest.config.ts projects
// and runs as its own CI step (same shape as web e2e).
export default defineConfig({
  test: {
    name: "site-e2e",
    include: ["test/e2e.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
