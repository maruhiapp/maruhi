// drizzle-kit v1 のフォルダ形式(drizzle/<name>/migration.sql)を
// cloudflare:test の applyD1Migrations が受け取る D1Migration[] へ読み込む。
// @cloudflare/vitest-plugin 同梱の readD1Migrations はフラットな *.sql のみ対応のため自前で読む。
// Node(vitest.config.ts)専用 — テスト本体(workerd)から import しないこと。

import { readdirSync, readFileSync } from "node:fs";

export interface D1MigrationInput {
  readonly name: string;
  readonly queries: readonly string[];
}

export function readDrizzleMigrations(migrationsDir: string): D1MigrationInput[] {
  return readdirSync(migrationsDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .toSorted()
    .map((name) => ({
      name,
      queries: readFileSync(`${migrationsDir}/${name}/migration.sql`, "utf8")
        .split("--> statement-breakpoint")
        .map((query) => query.trim())
        .filter((query) => query.length > 0),
    }));
}
