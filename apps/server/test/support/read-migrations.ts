// Loads drizzle-kit v1's folder form (drizzle/<name>/migration.sql) into the
// D1Migration[] that cloudflare:test's applyD1Migrations accepts.
// The readD1Migrations bundled with @cloudflare/vitest-plugin only supports
// flat *.sql files, so this reads them itself.
// Node (vitest.config.ts) only — do not import from the test bodies
// (workerd).

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
