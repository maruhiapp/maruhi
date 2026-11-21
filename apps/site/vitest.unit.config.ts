import { defineConfig } from "vite-plus/test/config";

export default defineConfig({
  test: {
    name: "site-unit",
    include: ["test/unit/**/*.test.ts"],
  },
});
