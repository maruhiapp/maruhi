// D1(sqlite)の drizzle-kit 設定(ADR-0006)。
// generate 専用: マイグレーション SQL は wrangler の d1 migrations(本番)と
// applyD1Migrations(テスト)が適用する。push / 実 DB 接続はここでは使わない。

import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dialect: "sqlite",
  schema: "./src/db.package/schema.ts",
  out: "./drizzle",
});
