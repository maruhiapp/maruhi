import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { unstable_readConfig } from "wrangler";

import { fakeGitHub } from "./test/support/fake-github.ts";
import { readDrizzleMigrations } from "./test/support/read-migrations.ts";

// serving-topology.test.ts(run_worker_first の全エンドポイント被覆スイープ)へ
// wrangler.jsonc の実値を渡す。workerd 内から fs を読めないため Node 側で読む
const wranglerConfig = unstable_readConfig({
  config: new URL("wrangler.jsonc", import.meta.url).pathname,
});

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
          // デプロイメント keypair の IKM(CRYPTO_SPEC §9)。本番では Workers
          // Secret。リース経路(§14)のテストは、この IKM から導出される実鍵で
          // サーバー宛ラップを作り、サーバーがそれを開封できることまで検証する
          SERVER_ENC_KEY_IKM: "b0".repeat(32),
          // wrangler.jsonc の assets.run_worker_first の実値(被覆スイープの検査対象)
          TEST_RUN_WORKER_FIRST: (wranglerConfig.assets?.run_worker_first ?? null) as string[],
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
    // 遅い CI ランナー(2 コア)ではベクター駆動のチェーン再生テストが
    // 30s 超の実測もある(2026-08-31 の CI run 33416421984)。ハング検出の
    // 有界性は保ったまま余裕を持たせる
    testTimeout: 60_000,
    // データプレーンの fixture(beforeEach)は PAT をユーザーごとに実経路
    // (CLI ログインハンドオフ = 6 往復 — AUTH_SPEC §11-1 の裁定でスタブ不可)
    // で発行してからベースチェーンを API 再生するため、既定 10s では負荷次第で
    // 超える(実測フレーク)。同じくハング検出は保ったまま余裕を持たせる
    hookTimeout: 30_000,
  },
});
