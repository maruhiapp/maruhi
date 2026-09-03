import { cloudflareTest } from "@cloudflare/vitest-plugin";
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
        // 運用基盤 H3 の退避先(ローカル R2 — wrangler.jsonc の最上位には無い optional
        // バインディング。hosted 環境の形をテストで再現する)
        r2Buckets: ["OPS_BACKUP_BUCKET"],
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
          // トリップワイヤ通知の webhook(hosted-ops.md §2-B)。フェイク(fake-github.ts)が
          // 受ける。送信本文の検査は OpsNotifier の差し替えで行う(ops-alerts.test.ts)
          OPS_ALERT_WEBHOOK_URL: "https://ops-webhook.test/hook",
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
    // ファイルごとに workerd を作り直さず、ワーカー(既定 = コア数 - 1)ごとに
    // 1 つの workerd を使い回す(2026-09-03)。既定の isolate: true ではテスト
    // ファイル 1 本ごとに Effect + サーバー本体の再 import(実測 5〜6s/ファイル、
    // 50 ファイルで合計 ~290s CPU)が走り、これがスイート時間の過半を占めていた。
    // 実測(4 コア): 壁時計 160s → 51s。
    //
    // トレードオフ: 同じワーカーが処理するファイル間で D1 / DO / R2 のストレージが
    // 共有される(vitest-plugin 1.x の分離単位は「ワーカー」)。このスイートの
    // fixture は元々ファイル内のテスト間でも分離を前提にしておらず、beforeEach で
    // D1 の認証系テーブル全消去(support/auth.ts resetAuthDb)と対象プロジェクト DO
    // のリセット(support/project-do.ts)を行うため、ファイル境界を跨いでも同じ
    // 規律で成り立つ。全 50 ファイルを 1 ワーカー直列・シャッフル順で流しても
    // 全件通過することを確認済み。ファイル間の状態依存が疑われる flake が出た
    // 場合は、まず当該ファイルの fixture が「自分の前提状態を自分で作る」規律を
    // 守っているかを確認する(isolate を戻すのは最後の手段)。R2(OPS_BACKUP_BUCKET)
    // はリセットしていない: バケットを読むテストは必ず自ファイル固有のプレフィックス
    // で絞る(ops-backup.test.ts の `oversize-test/<doId>/` が現状の唯一の例)。
    //
    // 前提: @cloudflare/vitest-plugin 1.1.2 以降。それ以前(vitest-pool-workers
    // 0.22.0 まで)は SELF.fetch のリクエスト単価が累積リクエスト数に比例して増える
    // ハーネス側の不具合(workers-sdk#15092 / #15446 — 実測 2ms → 125ms/req @800
    // リクエスト)があり、workerd を使い回すとスイート全体が二次的に遅くなっていた
    // (PR #120 のファイル分割はその回避策)。
    isolate: false,
    // 通過したテストの console 出力は捨てる。サーバーは応答ごとに Effect の
    // HttpMiddleware.logger が INFO 行("Sent HTTP response")を出すため、CI の
    // 1 run でログ 1 万数千ブロック(約 9.7 万行)になり、読めない上に転送・描画
    // コストも払っていた。失敗したテストの出力は従来どおり全部表示される
    silent: "passed-only",
  },
});
