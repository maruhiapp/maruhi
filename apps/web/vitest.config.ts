import { defineConfig } from "vite-plus/test/config";

export default defineConfig({
  test: {
    name: "web-e2e",
    include: ["test/e2e.test.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
