import { defineConfig } from "vite-plus/test/config";

export default defineConfig({
  test: {
    name: "web-unit",
    include: ["test/unit/**/*.test.ts"],
  },
});
