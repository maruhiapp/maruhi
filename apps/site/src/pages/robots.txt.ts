import { withBase } from "@cloudflare/nimbus-docs/runtime";
import { config } from "virtual:nimbus/config";

export const prerender = true;

export function GET() {
  const body = [
    "User-agent: *",
    // No Content Signals line: maruhi has not decided an AI-use policy, so
    // this file makes no such declaration (the scaffold's default line
    // declared ai-train=yes; a policy statement is the owner's to make).
    "Allow: /",
    "",
    `Sitemap: ${new URL(withBase("/sitemap-index.xml", import.meta.env.BASE_URL), config.site).href}`,
    "",
  ].join("\n");

  return new Response(body, {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}
