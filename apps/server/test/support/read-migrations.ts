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
