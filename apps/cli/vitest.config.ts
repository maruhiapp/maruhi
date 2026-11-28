import { configDefaults, defineConfig } from "vite-plus/test/config";

export default defineConfig({
  test: {
    name: "cli",
    exclude: [...configDefaults.exclude, "test/e2e.test.ts"],
  },
});
