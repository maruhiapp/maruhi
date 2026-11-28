import { defineConfig } from "vite-plus/test/config";

export default defineConfig({
  test: {
    name: "cli-e2e",
    include: ["test/e2e.test.ts"],
    bail: 1,
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
