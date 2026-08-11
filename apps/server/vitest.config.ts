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
          // GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET は本番では Workers Secret
          // (wrangler.jsonc には現れない)のため、テストは「設定済みサーバー」の
          // ダミー値をここで注入する(未設定検出のテストは worker.fetch に env を
          // 差し替えて渡す — auth.test.ts)
          GITHUB_CLIENT_ID: "dummy-github-client-id",
          GITHUB_CLIENT_SECRET: "dummy-github-client-secret",
          // D1 マイグレーション(test 側で applyD1Migrations に渡す)。
          // パスは設定ファイル基準(ルートの vitest run でも壊れないよう絶対化)
          // Miniflare bindings は Record<string, Json>。D1Migration[] は JSON 互換だが
          // interface に index signature が無いため、Json 代入用に広げて渡す
          // (vitest-pool-workers 0.21 / miniflare 5 の型厳密化)。
          TEST_MIGRATIONS: readDrizzleMigrations(
            new URL("drizzle/", import.meta.url).pathname,
          ) as Array<{
            name: string;
            queries: string[];
            [key: string]: string | string[];
          }>,
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
