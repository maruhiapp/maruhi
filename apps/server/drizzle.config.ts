// drizzle-kit config for D1 (sqlite) (ADR-0006).
// generate only: migration SQL is applied by cf d1 migrations (production)
// and applyD1Migrations (tests). push / live DB connections are not used here.

import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dialect: "sqlite",
  schema: "./src/db.package/schema.ts",
  out: "./drizzle",
});
