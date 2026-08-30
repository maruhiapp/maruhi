import { defineConfig } from "vitest/config";

// web ダッシュボードのユニットテスト(純粋関数 — API 消費層・チェーン表示導出)。
// e2e(vitest.config.ts — ビルド済み dist + wrangler dev 前提)と違い、ビルド
// なしで走るためルート vitest.config.ts の projects に載せる(品質ゲート 7 の
// 経路)。DOM・ブラウザ・ネットワークを使わない(fetch はテスト内でスタブする)。
export default defineConfig({
  test: {
    name: "web-unit",
    include: ["test/unit/**/*.test.ts"],
  },
});
