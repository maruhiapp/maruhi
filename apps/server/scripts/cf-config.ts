// Shared cloudflare.config.ts resolution for the ops scripts (d1-id.ts,
// d1-export.ts): evaluates the config function for a cf --mode and returns the
// worker's D1 binding. `cf d1` subcommands take the database ID — never the
// binding or database name.

import type { D1Binding } from "cf/config";

import cfConfig from "../cloudflare.config.ts";

/** A D1 binding that names its database ID (what `cf d1` subcommands take). */
function isD1WithId(binding: { readonly type: string }): binding is D1Binding & { id: string } {
  return binding.type === "d1" && (binding as D1Binding).id !== undefined;
}

export function cfD1Binding(mode: string | undefined, caller: string) {
  const worker = cfConfig({ isPreview: false, mode }).worker;
  const db = Object.values(worker.env ?? {}).find(isD1WithId);
  if (db === undefined) {
    console.error(
      `${caller}: no D1 binding with an id in cloudflare.config.ts for mode ${JSON.stringify(mode)}`,
    );
    process.exit(1);
  }
  return db;
}

// The D1 export/import envelopes carry signed URLs for unencrypted dumps; a
// thrown error string ends up in CI logs, so URL-shaped values are scrubbed
// before raw API output is interpolated into errors.
export function redactUrls(text: string): string {
  return text.replace(/https?:\/\/\S+/g, "[redacted-url]");
}
