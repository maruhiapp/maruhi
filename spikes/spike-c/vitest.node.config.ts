import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "spike-c-node",
    include: ["test/hpke.test.ts"],
  },
});
