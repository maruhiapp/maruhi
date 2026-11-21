import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import config from "../cloudflare.config.ts";

const siteRoot = join(import.meta.dirname, "..");

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
        directory: "../dist",
        html_handling: assets.htmlHandling,
        not_found_handling: assets.notFoundHandling,
      },
    },
    null,
    2,
  )}\n`;
}

export function writeWranglerConfig(): string {
  const path = join(siteRoot, ".cloudflare", "preview-wrangler.jsonc");
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, wranglerConfigJson());
  return path;
}
