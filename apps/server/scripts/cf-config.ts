// Shared cloudflare.config.ts resolution for the ops scripts (d1-id.ts,
// d1-export.ts): evaluates the config function for a cf --mode and returns the
// worker's D1 binding. `cf d1` subcommands take the database ID — never the
// binding or database name.

import cfConfig from "../cloudflare.config.ts";

export function cfD1Binding(mode: string | undefined, caller: string) {
  const worker = cfConfig({ isPreview: false, mode }).worker;
  const db = Object.values(worker.env ?? {}).find((binding) => binding.type === "d1");
  if (db === undefined || db.type !== "d1") {
    console.error(
      `${caller}: no D1 binding in cloudflare.config.ts for mode ${JSON.stringify(mode)}`,
    );
    process.exit(1);
  }
  return db;
}
