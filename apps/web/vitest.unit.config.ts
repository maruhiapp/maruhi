import { defineConfig } from "vitest/config";

// Unit tests for the web dashboard (pure functions — the API
// consumption layer and the chain-view derivation). Unlike e2e
// (vitest.config.ts — assumes a prebuilt dist + cf dev), these run
// with no build, so they are listed in the root vitest.config.ts
// projects (the quality-gate 7 path). No DOM, browser, or network is
// used (fetch is stubbed inside the tests). styling-lint.test.ts also
// runs oxlint on probe files in a temporary tree, to check that the
// styling bans of .oxlintrc.json reach the web's files.
export default defineConfig({
  test: {
    name: "web-unit",
    include: ["test/unit/**/*.test.ts"],
  },
});
