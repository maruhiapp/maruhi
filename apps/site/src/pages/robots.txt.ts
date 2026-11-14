import { withBase } from "@cloudflare/nimbus-docs/runtime";
import { config } from "virtual:nimbus/config";

export const prerender = true;

export function GET() {
  const body = [
    "User-agent: *",
    // Content Signals, declared deliberately (owner decision 2026-11-14):
    // maruhi's documentation is written to be used, including by AI
    // systems — the site already serves LLM-consumable full-text
    // endpoints for that purpose, and the same content is public in
    // the repository. All three uses are permitted; revisit if the
    // site ever publishes content whose value lies in restricting them.
    "Content-Signal: ai-train=yes, search=yes, ai-input=yes",
    "Allow: /",
    "",
    `Sitemap: ${new URL(withBase("/sitemap-index.xml", import.meta.env.BASE_URL), config.site).href}`,
    "",
  ].join("\n");

  return new Response(body, {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}
