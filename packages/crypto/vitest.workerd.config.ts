// Runs the tests under workerd (the real Cloudflare Workers environment) (CRYPTO_SPEC §11).
// Not picked up by the root vitest.config.ts glob (packages/*/vitest.config.ts);
// run from a dedicated CI step / `bun run test:workerd` (the spike-c setup).
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vite-plus/test/config";

import { vitestPoolAliases } from "../../scripts/vitest-aliases.ts";

export default defineConfig({
  // The Cloudflare pool's in-workerd entry (see scripts/vitest-aliases.ts).
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
