import type { D1Binding } from "cf/config";

import cfConfig from "../cloudflare.config.ts";

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

export function redactUrls(text: string): string {
  return text.replace(/https?:\/\/\S+/g, "[redacted-url]");
}
