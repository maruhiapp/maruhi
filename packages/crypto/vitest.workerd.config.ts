import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vite-plus/test/config";

import { vitestPoolAliases } from "../../scripts/vitest-aliases.ts";

export default defineConfig({
  resolve: { alias: vitestPoolAliases },
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
    }),
  ],
  test: {
    name: "crypto-workerd",
    include: ["test/**/*.test.ts"],
  },
});
