import { createHash } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const publicDir = join(import.meta.dirname, "..", "dist", "public");
const themeSource = join(import.meta.dirname, "..", "theme", "maruhi.css");

writeFileSync(join(publicDir, "theme.css"), readFileSync(themeSource));
const html = readFileSync(join(publicDir, "index.html"), "utf8");

const inlineScripts = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)]
  .map((m) => m[1] ?? "")
  .filter((body) => body.length > 0);

if (inlineScripts.length !== 1) {
  throw new Error(
    `expected exactly 1 inline bootstrap script, found ${inlineScripts.length}. ` +
      "funstack-static's output format may have changed. Re-check the CSP generation logic",
  );
}

const hashes = inlineScripts.map(
  (body) => `'sha256-${createHash("sha256").update(body, "utf8").digest("base64")}'`,
);

const astryxLayerSlideRulesHash = "'sha256-/i2+VVt2qoVh0Ag9OWwyc9593DCZeYGAv6SliqVbheY='";

const csp = [
  "default-src 'none'",
  `script-src 'self' ${hashes.join(" ")}`,
  `style-src 'self' ${astryxLayerSlideRulesHash}`,
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const inviteHtml = readFileSync(join(publicDir, "invite.html"), "utf8");

if (/<script/i.test(inviteHtml)) {
  throw new Error(
    "invite.html contains a <script>. /invite carries no scripts at all (AUTH_SPEC §15-3)",
  );
}
if (/\bon[a-z]+\s*=\s*["']/i.test(inviteHtml)) {
  throw new Error("invite.html has an inline event-handler attribute (AUTH_SPEC §15-3)");
}
if (/javascript:/i.test(inviteHtml)) {
  throw new Error("invite.html has a javascript: URL (AUTH_SPEC §15-3)");
}
const metaCspMatch = inviteHtml.match(
  /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"/i,
);
if (metaCspMatch?.[1] === undefined || !metaCspMatch[1].includes("script-src 'none'")) {
  throw new Error("invite.html lacks a meta CSP (script-src 'none') (AUTH_SPEC §15-3)");
}
const allowedExternalNavPrefix = "https://github.com/maruhiapp/maruhi";
for (const [, attr, url] of inviteHtml.matchAll(/\b(src|href)="([^"]*)"/g)) {
  const ok =
    url !== undefined &&
    ((url.startsWith("/") && !url.startsWith("//")) ||
      url.startsWith("#") ||
      (attr === "href" && url.startsWith(allowedExternalNavPrefix)));
  if (!ok) {
    throw new Error(`invite.html references an external resource/URL: ${attr}="${url}"`);
  }
}
const sourceDir = join(import.meta.dirname, "..", "public");
for (const asset of ["invite.html", "pages.css"]) {
  if (
    readFileSync(join(sourceDir, asset), "utf8") !== readFileSync(join(publicDir, asset), "utf8")
  ) {
    throw new Error(
      `${asset} differs between source and build output (the assumption of an untransformed publicDir copy is broken)`,
    );
  }
}

const pagesCss = readFileSync(join(sourceDir, "pages.css"), "utf8");
const themeCss = readFileSync(themeSource, "utf8");
const TOKEN_REF = /var\(\s*(--[a-z0-9-]+)/g;
const tokenDefinitions = new Map<string, string>();
for (const m of themeCss.matchAll(/(--[a-z0-9-]+)\s*:([^;{}]*);/g)) {
  if (!tokenDefinitions.has(m[1]!)) tokenDefinitions.set(m[1]!, m[2]!);
}
const unresolvedPaths: string[] = [];
const visited = new Set<string>();
function resolveToken(token: string, path: readonly string[]): void {
  const value = tokenDefinitions.get(token);
  if (value === undefined) {
    unresolvedPaths.push(path.join(" -> "));
    return;
  }
  if (visited.has(token)) return;
  visited.add(token);
  for (const m of value.matchAll(TOKEN_REF)) resolveToken(m[1]!, [...path, m[1]!]);
}
for (const m of pagesCss.matchAll(TOKEN_REF)) resolveToken(m[1]!, [m[1]!]);
if (unresolvedPaths.length > 0) {
  throw new Error(
    "pages.css token references do not resolve to a value in theme/maruhi.css: " +
      `${[...new Set(unresolvedPaths)].join(", ")}` +
      "(script-free pages read no token source other than /theme.css)",
  );
}

const bundleFiles = [
  join(publicDir, "index.html"),
  ...readdirSync(publicDir, { recursive: true, encoding: "utf8" })
    .filter((name) => name.endsWith(".js") || name.endsWith(".mjs"))
    .map((name) => join(publicDir, name)),
];
for (const file of bundleFiles) {
  const content = readFileSync(file, "utf8");
  if (/\bhash\b/i.test(content)) {
    throw new Error(
      `${file} contains the word "hash". The SPA bundle never reads the fragment (AUTH_SPEC §15-3 — ` +
        "to add a legitimate use, amend docs/notes/session-41.md ruling BG)",
    );
  }
}

const inviteCsp = [
  "default-src 'none'",
  "script-src 'none'",
  "style-src 'self'",
  "img-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

const headers = `/*
  Content-Security-Policy: ${csp}
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  Strict-Transport-Security: max-age=31536000

/invite
  ! Content-Security-Policy
  Content-Security-Policy: ${inviteCsp}
`;

writeFileSync(join(publicDir, "_headers"), headers);

const written = readFileSync(join(publicDir, "_headers"), "utf8");
const inviteBlock = written.split(/^(?=\/)/m).find((block) => block.startsWith("/invite\n"));
if (inviteBlock === undefined || !inviteBlock.includes("script-src 'none'")) {
  throw new Error("_headers lacks the /invite per-path CSP (script-src 'none')");
}

const inviteRedirectRules: string[] = ["/invite /invite 200"];
for (let bits = 1; bits < 1 << "invite".length; bits++) {
  let variant = "";
  for (let i = 0; i < "invite".length; i++) {
    const ch = "invite".charAt(i);
    variant += (bits >> i) & 1 ? ch.toUpperCase() : ch;
  }
  inviteRedirectRules.push(`/${variant}* /invite 301`);
}
inviteRedirectRules.push("/invite* /invite 301");
writeFileSync(join(publicDir, "_redirects"), `${inviteRedirectRules.join("\n")}\n`);

const writtenRedirects = readFileSync(join(publicDir, "_redirects"), "utf8");
for (const required of ["/invite /invite 200", "/Invite* /invite 301", "/invite* /invite 301"]) {
  if (!writtenRedirects.includes(required)) {
    throw new Error(`_redirects lacks the normalization rule: ${required}`);
  }
}
if (
  writtenRedirects.indexOf("/invite /invite 200") > writtenRedirects.indexOf("/invite* /invite 301")
) {
  throw new Error(
    "_redirects ordering is broken: the 200-rewrite shield sits after the /invite* catch-all",
  );
}

console.log(
  `_headers written (${hashes.length} inline script hash + 1 pinned style hash + /invite per-path CSP), ` +
    `_redirects written (${inviteRedirectRules.length} rules), ` +
    `pages.css tokens resolved against theme.css (${visited.size} reached, 0 unresolved)`,
);
