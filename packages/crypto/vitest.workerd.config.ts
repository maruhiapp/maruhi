// workerd(Cloudflare Workers 実環境)でのテスト実行(CRYPTO_SPEC §11)。
// ルート vitest.config.ts の glob(packages/*/vitest.config.ts)には載せず、
// CI の独立ステップ / `bun run test:workerd` から実行する(spike-c の構成)。
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
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
