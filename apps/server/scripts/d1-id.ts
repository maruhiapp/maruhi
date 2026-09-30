// Prints the D1 database ID (UUID) configured for a cf mode in
// cloudflare.config.ts. `cf d1` subcommands take the database ID — never the
// binding or database name — so package.json scripts / runbooks resolve it
// from the config instead of hard-coding it.
//
// Usage (from apps/server): bun scripts/d1-id.ts [mode]
//   (no mode = the self-host default; "hosted" = the operator's DB)

import { cfD1Binding } from "./cf-config.ts";

const mode = process.argv[2];
console.log(cfD1Binding(mode, "d1-id").id);
