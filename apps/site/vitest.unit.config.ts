import { defineConfig } from "vitest/config";

// Unit tests for the apex site (Blume): that the generated theme artifacts
// (theme.css / tokens.ts / logo-dark.svg / duplicated assets) match a
// regeneration from apps/web/theme/maruhi.css (drift detection for ruling B).
// Runs without a build, so it is on the root vitest.config.ts projects
// (quality gate 7).
export default defineConfig({
  test: {
    name: "site-unit",
    include: ["test/unit/**/*.test.ts"],
  },
});
