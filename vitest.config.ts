import { defineConfig } from "vite-plus/test/config";

import { vitestPoolAliases } from "./scripts/vitest-aliases.ts";

// See ADR-0021.
export default defineConfig({
  resolve: { alias: vitestPoolAliases },
  test: {
    sequence: {
      shuffle: { files: true },
    },
    projects: [
      "packages/*/vitest.config.ts",
      "apps/cli/vitest.config.ts",
      "apps/server/vitest.config.ts",
      "apps/web/vitest.unit.config.ts",
      "apps/site/vitest.unit.config.ts",
    ],
  },
});
