// Generates the _headers for Workers Static Assets after the build.
// funstack-static embeds an inline <script id="_R_"> bootstrap into
// index.html (RSC-payload manifest setup + dynamic import of the entry).
// Because its contents change every build (it embeds the payload's
// content hash), the CSP permits only that script's SHA-256 hash instead
// of 'unsafe-inline'. This keeps "effectively script-src 'self'".
// Verification notes: docs/notes/spike-a.md
//
// It also fixes /invite (the invite-link landing page — AUTH_SPEC §15-3 /
// ADR-0018 amendment 2, item 5) structurally on its invariant "carries no
// scripts at all, never interprets the fragment" via:
//   (1) a mechanical check of the shipped invite.html (zero script, meta
//       CSP present, no external resources)
//   (2) writing the per-path CSP `script-src 'none'` into _headers and
//       verifying the final artifact
//   (3) generating a _redirects that normalizes near-miss paths (case
//       variants, deeper paths) to /invite
// Violations fail the build (throw) — the checks ride the quality-gate
// path (the web build step in CI). Ruling history: docs/notes/session-41.md.
//
// The shared styles of the script-free pages (/invite + the server-served
// ceremony pages — DP4) live in public/pages.css (self-hosted), and the
// brand values are read via var() from theme/maruhi.css (`astryx theme
// build` output = the generated source of truth of the brand), which is
// **bundled verbatim as /theme.css** (ruling DP4-B —
// docs/notes/web-design-pass.md §5; there is no generator script and no
// copy: the shipped file IS the theme file). This script does the
// bundling and checks byte equality.
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const publicDir = join(import.meta.dirname, "..", "dist", "public");
const themeSource = join(import.meta.dirname, "..", "theme", "maruhi.css");

// ---- /theme.css: verbatim bundling of the brand theme (DP4 ruling B) ----
// vite folds theme/maruhi.css into the SPA CSS bundle (content-hash
// name), so static HTML / server-rendered HTML have no stable name to
// reference. Put the same artifact under a fixed name (not duplicate
// management — a copy of identical bytes, pinned by the equality check
// below)
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

const csp = [
  "default-src 'none'",
  `script-src 'self' ${hashes.join(" ")}`,
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

// ---- /invite: mechanical check of the shipped file (pinning check 1) ----
// The checked target is not the source but the build output
// (dist/public/invite.html). Every path by which a script could slip
// into the served bytes (build transform, copy omission) is checked.
// The whole served bytes are checked (HTML comments are not stripped —
// the literal text of a script opening tag stays at zero even inside a
// comment. Same strength as the e2e-side check)
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
// The meta CSP (enforcement built into the served bytes) must exist and
// contain script-src 'none'. It is a second layer independent of the
// _headers per-path CSP (the serving layer), keeping script execution at
// zero regardless of serving-layer behavior differences (e.g. the
// production implementation of detached syntax)
const metaCspMatch = inviteHtml.match(
  /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"/i,
);
if (metaCspMatch?.[1] === undefined || !metaCspMatch[1].includes("script-src 'none'")) {
  throw new Error("invite.html lacks a meta CSP (script-src 'none') (AUTH_SPEC §15-3)");
}
// No external resource loading (every asset self-hosted — stylesheet /
// logo SVG / favicon are root-relative). Only the href attribute may
// point at this repo's GitHub (a navigation link funneling to CLI
// installation). Runtime enforcement is the CSP's job (default-src
// 'none' baseline); this check is a second layer to fail earlier at
// build time
// (protocol-relative `//` is rejected, distinguished from
// root-relative)
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
// Copy fidelity (ruling BH): pin by byte equality that the vite
// publicDir copy is untransformed (= the reviewed source text is the
// served bytes as-is). Detects, fastest, a future build plugin that
// starts transforming HTML/CSS. /theme.css is out of scope: this script
// itself writes it verbatim above (not via vite), so it always matches
// within the same run (the token-resolution check below carries the
// /theme.css contract instead)
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

// ---- pages.css token-resolution check (DP4 amendment 1) ----
// The only token source the script-free pages read is /theme.css (=
// theme/maruhi.css); the Astryx core stylesheets the dashboard
// additionally loads (reset.css / astryx.css) never reach them. Because
// theme/maruhi.css contains tokens that **reference but never define**
// Astryx-core tokens (the font-weight family), a `var(--…)` in pages.css
// that theme/maruhi.css does not define silently falls as an unresolved
// var() — invalid at computed-value time (the first version lost every
// font-weight that way). The build pins that references resolve **to a
// value**: name existence is not enough — theme/maruhi.css has 16+
// tokens that are "defined, but whose value references an Astryx-core
// token via var()" (`--text-heading-1-weight: var(--font-weight-semibold)`
// etc.); if pages.css uses one, the name check passes while the value
// fails (walk transitively and fail with the path when hitting an
// undefined token).
// Fallback-bearing `var(--x, …)` is not used in pages.css (amendment 1
// ruling), so it is not considered
const pagesCss = readFileSync(join(sourceDir, "pages.css"), "utf8");
const themeCss = readFileSync(themeSource, "utf8");
const TOKEN_REF = /var\(\s*(--[a-z0-9-]+)/g;
const tokenDefinitions = new Map<string, string>();
for (const m of themeCss.matchAll(/(--[a-z0-9-]+)\s*:([^;{}]*);/g)) {
  // A same-name redeclaration (a var() reference in a variant scope) is
  // first-wins: the first declaration is the astryx-base / astryx-theme
  // brand value, and resolving the reference to it is enough
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

// ---- check that the SPA bundle never reads the fragment (ruling BG) ----
// Mid-word typos that escape the near-miss normalization (the _redirects
// below), like /invte, fall to the SPA shell. The basis of their
// harmlessness — "the SPA never reads the fragment" — is made a
// mechanical check of the shipped files rather than a convention:
// require that **the word `hash` as an identifier, property, or string
// never appears** in every shipped JS + index.html (including the inline
// bootstrap) (covers all literal shapes: location.hash / {hash}
// destructuring / ["hash"]; zero hits in the current bundle).
// This is a literal tripwire whose target is drift (a future feature
// slipping fragment-reading in). Manual `#` parsing of `location.href`
// or obfuscation (charCodeAt(35) etc.) is out of detection — a `#`-based
// literal check was rejected because it cannot in principle be told
// apart from legitimate uses (a color parser's startsWith(`#`), Intl
// number patterns, the RSC runtime's "path#export" module-reference
// split) and would false-positive (measured in session-41 ruling BG).
// If a legitimate `hash` use is ever needed, this check fails and forces
// an explicit ruling (same shape as the "exactly one inline script"
// check — a type that intentionally breaks on upstream change)
// The scan enumerates publicDir recursively: pinning it to non-recursive
// assets/ would let a build output-layout change (subdirectories, .mjs)
// shrink coverage without failing the check. Recursive enumeration keeps
// coverage self-maintaining
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

// /invite's per-path CSP: `script-src 'none'` enforces "never interprets
// the fragment" structurally. The page uses only self-hosted styles
// (/theme.css + /pages.css) and the logo SVG. Everything else is 'none'
// (same shape as the server-served ceremony pages' CSP — cli-pages.ts)
const inviteCsp = [
  "default-src 'none'",
  "script-src 'none'",
  "style-src 'self'",
  "img-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

// HSTS: workers.dev is preloaded, but this closes the first-connection
// downgrade when a custom domain is assigned via routes. includeSubDomains
// is not set (_headers only affects this app's responses; the subdomain
// structure of the deploy-target zone is the self-hosting side's
// jurisdiction — including it would be overreach)
//
// /invite block: `! Content-Security-Policy` detaches the /* CSP before
// replacing it (without detaching, two CSPs would be listed together and
// both enforced — the safe side, but unreadable intent). The other /*
// headers (nosniff / Referrer-Policy / HSTS) still apply to /invite.
// With the html_handling default (auto-trailing-slash), requests to
// /invite.html and /invite/ are normalized to /invite, so one per-path
// rule for /invite suffices (serving behavior is pinned by e2e)
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

// ---- _headers final-artifact verification (pinning check 2) ----
// Confirm on the written file that "_headers carries the /invite
// per-path CSP" (if a future edit of this script drops the write, the
// build still fails)
const written = readFileSync(join(publicDir, "_headers"), "utf8");
const inviteBlock = written.split(/^(?=\/)/m).find((block) => block.startsWith("/invite\n"));
if (inviteBlock === undefined || !inviteBlock.includes("script-src 'none'")) {
  throw new Error("_headers lacks the /invite per-path CSP (script-src 'none')");
}

// ---- _redirects: normalize near-miss paths to /invite ----
// Asset-key matching is case-sensitive, so case variants like `/Invite`
// match no asset and fall to the SPA fallback (a shell that carries
// scripts). The whole class of "case variant x any trailing continuation"
// — including systematic sources (mobile auto-capitalization, trailing
// paste junk [which lands on the lowercase path]) — is closed by
// 301-normalizing to /invite with a machine-generated _redirects (the
// browser keeps the fragment across a redirect).
//
// Layout (exploiting first-match-wins): ① the canonical path's 200
// rewrite (a rewrite to itself = pass-through) placed first as a shield
// → ② the 63 case-variant trailing splats `/{Variant}* /invite 301` →
// ③ the lowercase catch-all `/invite* /invite 301` last. With the shield
// first, ③ cannot misfire on the canonical path itself (a self-loop)
// (the stylesheet moved to /pages.css under DP4 and is now outside
// /invite*, so the old /invite.css shield is unneeded).
// All rules count as dynamic with a limit of 100 (excess lines are
// silently dropped — measured), so keep the total at 65. The
// conceivable failure mode is "only the shield drops and ③ survives" = a
// redirect loop for /invite (loss of availability; no confidentiality
// impact, and obvious the moment it is opened), but wrangler dev and
// production share the same assets-worker implementation, so there is no
// basis for selective omission. The e2e pins the whole behavior. The
// residue is only mid-word typos (/invte etc.) — the same class as any
// 404 path (the SPA side has no code that reads the fragment)
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

// Pinning check: the written _redirects actually contains the
// normalization rules, and the shield (the 200 rewrite) precedes the
// catch-all (/invite*) (the ordering invariant for loop safety under
// first-match-wins)
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
  `_headers written (${hashes.length} inline script hash + /invite per-path CSP), ` +
    `_redirects written (${inviteRedirectRules.length} rules), ` +
    `pages.css tokens resolved against theme.css (${visited.size} reached, 0 unresolved)`,
);
