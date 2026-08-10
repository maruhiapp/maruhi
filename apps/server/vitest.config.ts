import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

import { fakeGitHub } from "./test/support/fake-github.ts";
import { readDrizzleMigrations } from "./test/support/read-migrations.ts";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        // GitHub へのアウトバウンド fetch をフェイクに差し替える(実ネットワーク禁止)
        outboundService: fakeGitHub,
        bindings: {
          // wrangler.jsonc の vars はセルフホスト向けプレースホルダのため、
          // テストは「設定済みサーバー」のダミー値で上書きする(未設定検出の
          // テストは worker.fetch に env を差し替えて渡す — auth.test.ts)
          GITHUB_CLIENT_ID: "dummy-github-client-id",
          GITHUB_CLIENT_SECRET: "dummy-github-client-secret",
          // D1 マイグレーション(test 側で applyD1Migrations に渡す)。
          // パスは設定ファイル基準(ルートの vitest run でも壊れないよう絶対化)
          TEST_MIGRATIONS: readDrizzleMigrations(new URL("drizzle/", import.meta.url).pathname),
        },
      },
    }),
  ],
  test: {
    name: "server",
    // workerd 実環境の HTTP 往復が多いテスト(1 テスト 10 リクエスト超)は
    // スイート全体の負荷次第で既定 5s を超えることがある(実測フレーク)。
    // ハング検出の有界性は保ったまま余裕を持たせる
    testTimeout: 15_000,
  },
});
