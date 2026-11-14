// The wrangler-native rendering of cloudflare.config.ts's serving fields,
// for local serving of the built site (scripts/preview.ts and the site
// e2e).
//
// `cf dev` delegates to the framework's dev server when it detects one
// (Astro → `astro dev`), which serves the source tree, not the built
// output, and applies none of the production serving semantics (the
// _headers of Workers Static Assets, htmlHandling, notFoundHandling).
// Production deploys evaluate cloudflare.config.ts (worker name,
// compatibility date, assets handling) plus wrangler.config.ts (the
// assets directory). Rendering those values into the config format
// `wrangler dev` reads keeps preview and e2e serving the same bytes the
// same way production does — generated from the cf config, never a
// second hand-kept copy.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import config from "../cloudflare.config.ts";

const siteRoot = join(import.meta.dirname, "..");

/** The wrangler-native rendering of cloudflare.config.ts's serving fields. */
export function wranglerConfigJson(): string {
  const { name, compatibilityDate, assets } = config.worker;
  if (assets === undefined) {
    throw new Error("cloudflare.config.ts: worker.assets is required to serve the site");
  }
  return `${JSON.stringify(
    {
      name,
      compatibility_date: compatibilityDate,
      assets: {
        // Relative to the generated file (apps/site/.cloudflare/)
        directory: "../dist",
        html_handling: assets.htmlHandling,
        not_found_handling: assets.notFoundHandling,
      },
    },
    null,
    2,
  )}\n`;
}

/** Writes the generated config under .cloudflare/ and returns its path. */
export function writeWranglerConfig(): string {
  const path = join(siteRoot, ".cloudflare", "preview-wrangler.jsonc");
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, wranglerConfigJson());
  return path;
}
